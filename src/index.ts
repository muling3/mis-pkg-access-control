// @mis/access-control — authZ model + guard (PoC).
// Kong (jwt plugin) handles authN; this decides what the authenticated user
// — read off the request by @mis/auth-middleware — may do INSIDE a service.
export const PACKAGE = "@mis/access-control";

// ── 5 permissions ─────────────────────────────────────────────
export const PERMISSIONS = [
  "case:read",
  "case:write",
  "reporting:read",
  "reporting:export",
  "profile:read",
] as const;
export type Permission = (typeof PERMISSIONS)[number];

// ── 2 roles → permissions ─────────────────────────────────────
export const ROLES: Record<string, Permission[]> = {
  "case-officer": ["case:read", "case:write", "profile:read"],
  "reporting-analyst": ["reporting:read", "reporting:export", "profile:read"],
};

export interface Principal {
  id: string;
  roles: string[];
}

/** Flatten a set of role names to the permissions they grant. */
export function permissionsForRoles(roles: string[] = []): Permission[] {
  const out = new Set<Permission>();
  for (const r of roles) for (const p of ROLES[r] ?? []) out.add(p);
  return [...out];
}

export function hasRole(user: Principal | undefined, role: string): boolean {
  return !!user && user.roles.includes(role);
}

/** `admin` may do anything; otherwise the permission must be role-granted. */
export function can(
  user: Principal | undefined,
  permission: string,
): boolean {
  if (!user) return false;
  if (user.roles.includes("admin")) return true;
  return permissionsForRoles(user.roles).includes(permission as Permission);
}

export interface AccessGuardOptions {
  /** Permission required for every route except `allow`. */
  permission: Permission;
  /** Exact request paths that skip the permission check (still need a token). */
  allow?: string[];
}

/**
 * Express/NestJS-style guard. Mount AFTER gatewayIdentity() so `req.user`
 * is populated. Whitelisted paths (`allow`) skip the check; everything else
 * needs `permission`. 403 with a helpful body otherwise.
 */
export function accessGuard(opts: AccessGuardOptions) {
  const allow = new Set(opts.allow ?? []);
  return (req: any, res: any, next: () => void) => {
    if (req.method === "OPTIONS" || allow.has(req.path)) return next();
    if (can(req.user, opts.permission)) return next();
    res.statusCode = 403;
    res.setHeader("content-type", "application/json");
    res.end(
      JSON.stringify({
        error: "forbidden",
        requiredPermission: opts.permission,
        yourRoles: req.user?.roles ?? [],
        yourPermissions: permissionsForRoles(req.user?.roles ?? []),
      }),
    );
  };
}

export function RequirePermission(permission: string): MethodDecorator {
  return (_t, _k, descriptor) => {
    (descriptor.value as any).__permission = permission;
    return descriptor;
  };
}

export function ResourceOwner(_opts: { entity: string; userField: string }): MethodDecorator {
  return (_t, _k, descriptor) => descriptor;
}

export function banner(): string {
  return `[${PACKAGE}] authz model loaded (${PERMISSIONS.length} perms, ${Object.keys(ROLES).length} roles)`;
}
