export class RoleConfig {
  role: string;
  expiresIn: string;

  constructor(role: string, expiresIn: string) {
    this.role = role;
    this.expiresIn = expiresIn;
  }
}

export const rolesConfig: RoleConfig[] = [
  new RoleConfig('OWNER', '30m'),
  new RoleConfig('ADMIN', '2h'),
  new RoleConfig('USER', '1h'),
];