export abstract class JwtConfig {}

export interface JwtConfig {
  readonly keysDirectory: string;
}
