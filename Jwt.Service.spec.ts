import { JsonWebTokenError, sign } from 'jsonwebtoken';
import { generateKeyPairSync } from 'crypto';

import { JwtService } from './Jwt.Service';
import { JwtConfig } from './JwtConfig';
import { RS256SigningKeyRepository } from './RS256SigningKey.Repository';
import { SigningKeyRepository } from './SigningKey.Repository';

describe('JwtService', () => {
  const config: JwtConfig = {
    keysDirectory: './keys',
  };

  let signingKeyRepository: SigningKeyRepository;
  let service: JwtService;

  beforeEach(() => {
    signingKeyRepository = new RS256SigningKeyRepository(config);
    service = new JwtService(signingKeyRepository);
  });

  test('generate JWT and verify claims', () => {
    // given
    const token = service.generate({
      email: 'john.doe@example.com',
      user_id: 'mockUserId',
    });

    // when
    const claims = service.verify(token);

    // then
    expect(claims.user_id).toBe('mockUserId');
    expect(claims.email).toBe('john.doe@example.com');
  });

  describe('fail verification', () => {
    test('if algorithm missing', () => {
      expect.hasAssertions();

      // given
      const token = sign(
        {
          email: 'john.doe@example.com',
          user_id: 'mockUserId',
        },
        'mockSecret',
        {
          algorithm: 'none',
        },
      );

      try {
        // when
        service.verify(token);
      } catch (e) {
        // then
        expect(e).toBeInstanceOf(JsonWebTokenError);
        expect(e.message).toBe('jwt signature is required');
      }
    });

    test('if algorithm invalid', () => {
      expect.hasAssertions();

      // given
      // generate custom jwt
      const ecKeypair = generateKeyPairSync('ec', {
        namedCurve: 'secp256k1',
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
        },
      });

      const token = sign(
        {
          email: 'john.doe@example.com',
          user_id: 'mockUserId',
        },
        ecKeypair.privateKey,
        {
          algorithm: 'ES256',
        },
      );

      try {
        // when
        service.verify(token);
      } catch (e) {
        // then
        expect(e).toBeInstanceOf(JsonWebTokenError);
        expect(e.message).toBe('invalid algorithm');
      }
    });

    test('if expired', () => {
      expect.hasAssertions();

      // given
      const token = sign(
        {
          exp: Math.floor(Date.now() / 1000) - 60 * 60,
          user_id: 'mockUserId',
          email: 'john.doe@example.com',
        },
        signingKeyRepository.getCurrentSigningKey(),
        {
          algorithm: 'RS256',
        },
      );

      // when
      try {
        service.verify(token);
      } catch (e) {
        expect(e).toBeInstanceOf(JsonWebTokenError);
        expect(e.message).toBe('jwt expired');
      }
    });
  });
});
