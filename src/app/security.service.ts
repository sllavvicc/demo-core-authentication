import {
  Injectable,
  Logger
} from '@nestjs/common';
import {
  AuthenticationsAccessTokens,
  AuthenticationsAccessTokensPayload
} from '@zozoboom/core-authentications/backend/dto';
import {
  AuthenticationsAccessGenarationInternalServerErrorException, AuthenticationsAccessRefreshTokenCheckBadException,
  AuthenticationsAccessTokenCheckBadException, AuthenticationsForgotTokenCheckBadException,
  AuthenticationsForgotTokenGenerationInternalServerErrorException,
  AuthenticationsPasswordBadException,
  AuthenticationsPasswordCheckInternalServerErrorException,
  AuthenticationsPasswordEncryptErrorException
} from '@zozoboom/core-authentications/backend/exception';
import { compare, hash } from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { from, Observable, of } from 'rxjs';
import { environment } from '../environments/environment';

@Injectable()
export class SecurityService {
  protected readonly _logger: Logger = new Logger('SecurityService');

  /**
   * @description Method used to encrypt provided raw password.
   * @param password Raw provided password
   * @returns {Observable<string>} String with encrypted password
   */
  public encryptPassword(password: string): Observable<string> {
    return from(hash(password, 10)
      .then((encryptedPassword) => encryptedPassword)
      .catch(() => {
        throw new AuthenticationsPasswordEncryptErrorException();
      })
    );
  }

  /**
   * @description Method used to check if provided raw password is valid
   * and same with encrypted password.
   * @param {string} password Raw provided password
   * @param encryptedPassword Encrypted password
   * @returns {Observable<boolean>} Boolean checking status
   */
  public checkPassword(
    password: string,
    encryptedPassword: string
  ): Observable<boolean> {
    return from(compare(password, encryptedPassword)
      .then((checkStatus) => {
        if (!checkStatus) {
          throw new AuthenticationsPasswordBadException();
        }
        return checkStatus;
      })
      .catch(() => {
        throw new AuthenticationsPasswordCheckInternalServerErrorException();
      })
    );
  }

  /**
   * @description Method used to generate access and refresh JWT tokens using
   * provided data on payload. 
   * @param {AuthenticationsAccessTokensPayload} payload Object with data used to write on JWT tokens
   * @returns {Observable<AuthenticationsAccessTokensPayload>} Object with access and refresh JWT tokens
   */
  public generateAccessTokens(
    payload: AuthenticationsAccessTokensPayload
  ): Observable<AuthenticationsAccessTokens> {
    try {
      const accessToken = jwt.sign(
        payload,
        environment.security.accessTokenSalt,
        {
          expiresIn: environment.security.accessTokenTTL,
        }
      );
      const refreshToken = jwt.sign(
        payload,
        environment.security.refreshTokenSalt,
        {
          expiresIn: environment.security.refreshTokenTTL,
        }
      );
      return of(
        new AuthenticationsAccessTokens({
          accessToken: accessToken,
          refreshToken: refreshToken,
        })
      );
    } catch (e) {
      throw new AuthenticationsAccessGenarationInternalServerErrorException();
    }
  }

  /**
   * @description Method used to verify if JWT access token is valid and payload is not changed.
   * If token is valid, this method decode JWT access token to object. 
   * @param {string} token JWT token
   * @returns {Observable<AuthenticationsAccessTokensPayload>} Decoded payload from JWT token 
   */
  public verifyAccessToken(
    token: string
  ): Observable<AuthenticationsAccessTokensPayload> {
    try {
      return of(
        new AuthenticationsAccessTokensPayload(
          jwt.verify(token, environment.security.accessTokenSalt)
        )
      );
    } catch (e) {
      throw new AuthenticationsAccessTokenCheckBadException();
    }
  }

  /**
   * @description Method used to verify if JWT refresh token is valid and payload is not changed.
   * If token is valid, this method decode JWT refresh token to object. 
   * @param {string} token JWT token
   * @returns {Observable<AuthenticationsAccessTokensPayload>} Decoded payload from JWT token 
   */
  public verifyRefreshToken(
    token: string
  ): Observable<AuthenticationsAccessTokensPayload> {
    try {
      return of(
        new AuthenticationsAccessTokensPayload(
          jwt.verify(token, environment.security.refreshTokenSalt)
        )
      );
    } catch (e) {
      throw new AuthenticationsAccessRefreshTokenCheckBadException();
    }
  }

  /**
   * @description Method used to generate JWT forgot token using
   * provided "userId" like a payload. This method use salt and TTL
   * from the ENV parameters. 
   * @param {string} userId String with user id used like a payload on JWT 
   * @returns {Observable<string>} Generated JWT token
   */
  public generateForgotToken(userId: string): Observable<string> {
    try {
      return of(
        jwt.sign({ userId }, environment.security.forgotTokenSalt, {
          expiresIn: environment.security.forgotTokenTTL,
        })
      );
    } catch (e) {
      throw new AuthenticationsForgotTokenGenerationInternalServerErrorException();
    }
  }

  /**
   * @description Method used to verify if JWT forgot token is valid and payload is not changed.
   * If token is valid, this method decode JWT forgot token to object.
   * @param {string} token JWT token
   * @returns {Observable<AuthenticationsAccessTokensPayload>} Decoded payload from JWT token 
   */
  public verifyForgotToken(
    token: string
  ): Observable<AuthenticationsAccessTokensPayload> {
    try {
      return of(
        new AuthenticationsAccessTokensPayload(
          jwt.verify(token, environment.security.forgotTokenSalt)
        )
      );
    } catch (e) {
      throw new AuthenticationsForgotTokenCheckBadException();
    }
  }

  /**
   * @description Method used to generate JWT approve token using
   * provided "userId" like a payload. This method use salt and TTL
   * from the ENV parameters. 
   * @returns {Observable<number>} Generated random number
   */
  public generateApproveCode(): Observable<number> {
    return of(
      Math.floor(
        environment.security.approveCodeMinValue +
        Math.random() * environment.security.approveCodeMaxValue
      )
    );
  }
}
