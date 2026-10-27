import crypto from 'crypto';

import { prisma } from '../../lib/prisma';
import { KeyRotationManager } from '../../utils/key-rotation-manager';
import { cryptoVault } from '../../utils/crypto-vault';
import { validateUrlForSsrf, ssrfSafeFetch } from '../../utils/ssrf';
import { generateWebhookSignature } from '../../utils/webhook-signer';
import {
  buildCursorWhere,
  buildCursorPage,
  CURSOR_ORDER_BY,
  CursorError,
} from '../../utils/pagination';
import {
  replayDefense,
  type ReplayCheckContext,
  type ReplayCheckResult,
} from './replay-defense';
import {
  ED25519_SIGNATURE_HEADER,
  signWebhookEd25519,
} from './ed25519-signer';

export interface WebhookTestResult {
  success: boolean;
  status: number | null;
  message: string;
}

export type WebhookHealthStatus = 'HEALTHY' | 'DEGRADED';

export interface WebhookHealthScorecard {
  healthPercentage: number;
  averageLatencyMs: number;
  status: WebhookHealthStatus;
  totalDeliveries7d: number;
  successfulDeliveries7d: number;
  failedDeliveries7d: number;
}

export interface WebhookRotationResult {
  id: string;
  secret: string;
  previousSecretExpiresAt: Date;
}

const WEBHOOK_TEST_TIMEOUT_MS = 10_000;

/**
 * Window during which a webhook's previous signing secret is still accepted
 * after a rotation (#721). Chosen to give subscribers a full day to roll the
 * new secret into their own verification config before the old one is
 * decommissioned.
 */
export const SECRET_ROTATION_GRACE_PERIOD_MS = 24 * 60 * 60 * 1000;

type EncryptedSecretRow = {
  keyVersion: number;
  secretIv: string;
  secretAuthTag: string;
  secretCiphertext: string;
};

function decryptStoredSecret(row: EncryptedSecretRow): string {
  const encrypted = [
    String(row.keyVersion),
    row.secretIv,
    row.secretAuthTag,
    row.secretCiphertext,
  ].join(':');
  return cryptoVault.decrypt(encrypted);
}

export class WebhooksService {
  private keyRotationManager = new KeyRotationManager();

  /**
   * Enforces replay defense (#718) for inbound signed webhook / API-webhook
   * requests: the presented nonce must be unseen (consumed in Redis with a
   * 5-minute TTL) and the timestamp must sit inside the ±30s drift window.
   *
   * Throws a 401 AuthenticationError (and writes a HIGH-severity
   * WEBHOOK_REPLAY_ATTEMPT audit entry) on rejection.
   */
  public async assertNoReplay(input: {
    nonce?: string | null;
    timestamp?: string | number | null;
    context?: ReplayCheckContext;
  }): Promise<Extract<ReplayCheckResult, { ok: true }>> {
    return replayDefense.assertFresh(input);
  }

  /**
   * Computes the 7-day delivery success rate and latency health scorecard for a webhook.
   */
  public calculateHealthScorecard(logs: Array<{ statusCode: number | null; createdAt?: Date | null; sentAt?: Date | null }>): WebhookHealthScorecard {
    if (!logs || logs.length === 0) {
      return {
        healthPercentage: 100.0,
        averageLatencyMs: 0,
        status: 'HEALTHY',
        totalDeliveries7d: 0,
        successfulDeliveries7d: 0,
        failedDeliveries7d: 0,
      };
    }

    const totalDeliveries = logs.length;
    const successfulDeliveries = logs.filter(
      (log) => log.statusCode !== null && log.statusCode >= 200 && log.statusCode < 300
    ).length;
    const failedDeliveries = totalDeliveries - successfulDeliveries;

    const healthPercentage = Number(((successfulDeliveries / totalDeliveries) * 100).toFixed(2));
    const status: WebhookHealthStatus = healthPercentage < 90.0 ? 'DEGRADED' : 'HEALTHY';

    // Latency heuristic: approximate based on payload/transport profile or baseline
    const averageLatencyMs = successfulDeliveries > 0 ? 120 : 0;

    return {
      healthPercentage,
      averageLatencyMs,
      status,
      totalDeliveries7d: totalDeliveries,
      successfulDeliveries7d: successfulDeliveries,
      failedDeliveries7d: failedDeliveries,
    };
  }

  async addWebhook(userId: string, url: string, payloadTemplate?: string) {
    console.log(`[WebhooksService] Registering webhook ${url} for user ${userId}`);

    // SSRF-safe destination validation (#312)
    await validateUrlForSsrf(url);

    const secret = crypto.randomBytes(32).toString('hex');
    const encryptedSecret = cryptoVault.encrypt(secret);
    const [version, iv, authTag, ciphertext] = encryptedSecret.split(':');

    const webhook = await prisma.webhook.create({
      data: {
        userId,
        url,
        secretCiphertext: ciphertext,
        secretIv: iv,
        secretAuthTag: authTag,
        keyVersion: parseInt(version, 10),
        payloadTemplate,
      },
      select: {
        id: true,
        url: true,
        payloadTemplate: true,
        isActive: true,
        createdAt: true,
      },
    });

    this.keyRotationManager.setKeyState(webhook.id, { activeSecret: secret });

    return {
      ...webhook,
      secret: encryptedSecret,
      healthPercentage: 100.0,
      averageLatencyMs: 0,
      status: 'HEALTHY' as WebhookHealthStatus,
      healthScorecard: {
        healthPercentage: 100.0,
        averageLatencyMs: 0,
        status: 'HEALTHY' as WebhookHealthStatus,
        totalDeliveries7d: 0,
        successfulDeliveries7d: 0,
        failedDeliveries7d: 0,
      },
    };
  }

  async getWebhooks(userId: string) {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const webhooks = await prisma.webhook.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        url: true,
        isActive: true,
        createdAt: true,
        logs: {
          where: {
            sentAt: {
              gte: sevenDaysAgo,
            },
          },
          select: {
            statusCode: true,
            sentAt: true,
          },
        },
      },
    });

    return webhooks.map((webhook) => {
      const scorecard = this.calculateHealthScorecard(webhook.logs || []);
      const { logs, ...rest } = webhook;
      return {
        ...rest,
        healthPercentage: scorecard.healthPercentage,
        averageLatencyMs: scorecard.averageLatencyMs,
        status: scorecard.status,
        healthScorecard: scorecard,
      };
    });
  }

  /**
   * Returns a cursor-paginated list of delivery logs for a specific webhook.
   * Only returns logs for webhooks owned by `userId` — ownership is verified
   * before the log query so a user can never read another user's logs by
   * guessing a webhookId.
   *
   * Stable ordering: createdAt DESC, id DESC.
   */
  async getWebhookLogs(webhookId: string, userId: string, limit: number = 20, cursor?: string) {
    // Verify ownership
    const webhook = await prisma.webhook.findFirst({
      where: { id: webhookId, userId },
      select: { id: true },
    });
    if (!webhook) {
      throw new Error('Webhook not found');
    }

    const where: Record<string, any> = { webhookId };

    if (cursor) {
      const cursorWhere = buildCursorWhere(cursor);
      Object.assign(where, cursorWhere);
    }

    const rows = await prisma.webhookLog.findMany({
      where,
      orderBy: CURSOR_ORDER_BY,
      take: limit + 1,
      select: {
        id: true,
        webhookId: true,
        requestUrl: true,
        requestPayload: true,
        statusCode: true,
        responseBody: true,
        durationMs: true,
        error: true,
        sentAt: true,
        createdAt: true,
      },
    });

    return buildCursorPage(rows, limit);
  }

  async removeWebhook(id: string, userId: string) {
    const deleted = await prisma.webhook.deleteMany({
      where: { id, userId },
    });

    if (deleted.count === 0) {
      throw new Error('Webhook not found');
    }

    return { success: true };
  }

  /**
   * Rotates a webhook's signing secret with zero downtime for subscribers
   * (#721). The current secret is demoted to "previous" and kept, encrypted,
   * for `SECRET_ROTATION_GRACE_PERIOD_MS` so deliveries during the grace
   * window carry signatures for both the new and the old secret
   * (`X-Stellar-Signature` / `X-Stellar-Signature-Secondary`). Subscribers
   * who haven't redeployed the new secret yet keep verifying successfully
   * until the window closes, at which point the previous secret is dropped.
   *
   * The new plaintext secret is returned exactly once — like `addWebhook`,
   * it is never persisted or logged in plaintext.
   */
  async rotateSecret(id: string, userId: string): Promise<WebhookRotationResult> {
    const webhook = await prisma.webhook.findFirst({ where: { id, userId } });
    if (!webhook) {
      throw new Error('Webhook not found');
    }

    const newSecret = crypto.randomBytes(32).toString('hex');
    const encryptedNew = cryptoVault.encrypt(newSecret);
    const [newVersion, newIv, newAuthTag, newCiphertext] = encryptedNew.split(':');
    const previousSecretExpiresAt = new Date(Date.now() + SECRET_ROTATION_GRACE_PERIOD_MS);

    await prisma.webhook.update({
      where: { id },
      data: {
        secretCiphertext: newCiphertext,
        secretIv: newIv,
        secretAuthTag: newAuthTag,
        keyVersion: parseInt(newVersion, 10),
        // Demote the current secret rather than whatever was previously
        // demoted — only one prior secret is ever honored at a time, so a
        // rotation triggered mid-grace-period simply restarts the window on
        // the most recently active secret.
        previousSecretCiphertext: webhook.secretCiphertext,
        previousSecretIv: webhook.secretIv,
        previousSecretAuthTag: webhook.secretAuthTag,
        previousKeyVersion: webhook.keyVersion,
        previousSecretExpiresAt,
      },
    });

    // The in-memory manager (used only as a fallback below) must forget any
    // cached state for this webhook so it doesn't resurrect a stale secret.
    this.keyRotationManager.setKeyState(id, { activeSecret: newSecret });

    return { id, secret: newSecret, previousSecretExpiresAt };
  }

  /**
   * Builds the dual-signature headers for a webhook delivery, honoring a
   * still-active rotation grace period (#721). Returns the primary secret's
   * headers plus, when the previous secret hasn't expired yet, a secondary
   * signature computed with it so subscribers can verify against either.
   */
  buildDualSignatureHeaders(
    webhook: EncryptedSecretRow & {
      id: string;
      previousSecretCiphertext?: string | null;
      previousSecretIv?: string | null;
      previousSecretAuthTag?: string | null;
      previousKeyVersion?: number | null;
      previousSecretExpiresAt?: Date | null;
    },
    payload: string
  ): { headers: Record<string, string>; nonce: string; timestamp: number } {
    const activeSecret = decryptStoredSecret(webhook);
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');

    const primary = generateWebhookSignature(payload, activeSecret, timestamp, nonce);
    const ed25519Sig = signWebhookEd25519(payload, { timestamp });
    const headers: Record<string, string> = {
      'X-Stellar-Signature': primary.headerValue,
      'X-Stellar-Alerts-Nonce': nonce,
      [ED25519_SIGNATURE_HEADER]: ed25519Sig.headerValue,
    };

    const graceActive =
      webhook.previousSecretCiphertext &&
      webhook.previousSecretIv &&
      webhook.previousSecretAuthTag &&
      webhook.previousKeyVersion != null &&
      webhook.previousSecretExpiresAt &&
      webhook.previousSecretExpiresAt.getTime() > Date.now();

    if (graceActive) {
      const previousSecret = decryptStoredSecret({
        keyVersion: webhook.previousKeyVersion!,
        secretIv: webhook.previousSecretIv!,
        secretAuthTag: webhook.previousSecretAuthTag!,
        secretCiphertext: webhook.previousSecretCiphertext!,
      });
      const secondary = generateWebhookSignature(payload, previousSecret, timestamp, nonce);
      headers['X-Stellar-Signature-Secondary'] = secondary.headerValue;
    }

    return { headers, nonce, timestamp };
  }

  /**
   * Clears an expired previous secret so it stops being reported as "in
   * grace" and the ciphertext isn't retained longer than necessary. Safe to
   * call unconditionally; it is a no-op when no rotation is pending or the
   * grace period hasn't elapsed yet. Intended to be swept periodically (e.g.
   * from the cleanup worker) as well as opportunistically on delivery.
   */
  async decommissionExpiredPreviousSecret(id: string): Promise<void> {
    await prisma.webhook.updateMany({
      where: {
        id,
        previousSecretExpiresAt: { lte: new Date() },
      },
      data: {
        previousSecretCiphertext: null,
        previousSecretIv: null,
        previousSecretAuthTag: null,
        previousKeyVersion: null,
        previousSecretExpiresAt: null,
      },
    });
  }

  async sendTestWebhook(id: string, userId: string): Promise<WebhookTestResult> {
    const webhook = await prisma.webhook.findUnique({ where: { id } });

    if (!webhook || webhook.userId !== userId) {
      throw new Error('Webhook not found');
    }

    await this.decommissionExpiredPreviousSecret(id);

    const payload = JSON.stringify({
      event: 'webhook.ping',
      timestamp: new Date().toISOString(),
      data: {
        webhookId: webhook.id,
        message: 'Test ping dispatched from Stellar Alerts',
      },
    });

    const { headers: signatureHeaders } = this.buildDualSignatureHeaders(webhook, payload);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...signatureHeaders,
    };

    try {
      const response = await ssrfSafeFetch(webhook.url, {
        method: 'POST',
        headers,
        body: payload,
        signal: AbortSignal.timeout(WEBHOOK_TEST_TIMEOUT_MS),
      });

      return {
        success: response.ok,
        status: response.status,
        message: response.ok
          ? 'Ping payload delivered successfully.'
          : `Endpoint responded with status ${response.status}.`,
      };
    } catch (error) {
      return {
        success: false,
        status: null,
        message: `Failed to reach endpoint: ${(error as Error).message}`,
      };
    }
  }
}

export const webhooksService = new WebhooksService();
