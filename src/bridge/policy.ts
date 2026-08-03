export class BalancedAuthorization {
  private authenticatedUntil = 0;
  private approvalDigests = new Map<string, number>();

  unlock(now = Date.now()): number {
    this.authenticatedUntil = now + 15 * 60_000;
    return this.authenticatedUntil;
  }

  status(): number {
    return this.authenticatedUntil;
  }

  isUnlocked(now = Date.now()): boolean {
    return this.authenticatedUntil >= now;
  }

  requireSession(now = Date.now()): void {
    if (this.authenticatedUntil < now) throw new Error("Face ID session is required or expired");
  }

  authorizeApproval(actionDigest: string, now = Date.now()): number {
    this.requireSession(now);
    const expiresAt = now + 60_000;
    this.approvalDigests.set(actionDigest, expiresAt);
    return expiresAt;
  }

  consumeApproval(actionDigest: string, now = Date.now()): void {
    const expiresAt = this.approvalDigests.get(actionDigest) ?? 0;
    this.approvalDigests.delete(actionDigest);
    if (expiresAt < now) throw new Error("Fresh Face ID is required for this exact approval");
  }
}
