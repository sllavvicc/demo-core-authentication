import {
  CACHE_MANAGER,
  ClassSerializerInterceptor,
  Controller,
  HttpException,
  Inject, UseFilters,
  UseInterceptors
} from '@nestjs/common';
import {
  ClientProxy,
  EventPattern,
  MessagePattern,
  Payload
} from '@nestjs/microservices';
import {
  AuthenticationsAccessTokensPayload,
  AuthenticationsRpcAccessTokenCheck,
  AuthenticationsRpcAccessTokens,
  AuthenticationsRpcAccessTokensRefresh
} from '@zozoboom/core-authentications/backend/dto';
import { AuthenticationsAccessNotFoundException } from '@zozoboom/core-authentications/backend/exception';
import { UsersRpc, UsersRpcWhere } from '@zozoboom/core-users/backend/dto';
import { HttpToRpcExceptionFilter } from '@zozoboom/core/backend/filter';
import { Cache } from 'cache-manager';
import { plainToClass } from 'class-transformer';
import { from, Observable, of, throwError } from 'rxjs';
import { catchError, map, mergeMap } from 'rxjs/operators';
import { environment } from '../environments/environment';
import { RepositoryService } from './repository.service';
import { SecurityService } from './security.service';

@Controller()
@UseFilters(HttpToRpcExceptionFilter)
export class RpcController {
  constructor(
    @Inject('RPC_SERVICE') private readonly _rpcClient: ClientProxy,
    @Inject(CACHE_MANAGER) private _cacheService: Cache,
    private readonly _repositoryService: RepositoryService,
    private readonly _securityService: SecurityService
  ) { }

  /**
   * @description Method to listen messages with authentication access JWT token
   * to verify if token is valid.
   * On receiving request, this method emit event with decoded JWT payload and after
   * successfully decoding data is returned on response.
   * @param {AuthenticationsRpcAccessTokenCheck} payload Object with access JWT token
   * @returns {Observable<AuthenticationsAccessTokensPayload>} Decoded JWT token payload
   */
  @MessagePattern('authentications.accessTokenVerify')
  @UseInterceptors(ClassSerializerInterceptor)
  public accessTokenVerify(
    @Payload() payload: AuthenticationsRpcAccessTokenCheck
  ): Observable<AuthenticationsAccessTokensPayload> {
    return this._securityService.verifyAccessToken(payload.accessToken).pipe(
      map((tokenPayload) => {
        this._rpcClient.emit<void, AuthenticationsAccessTokensPayload>(
          'authentications.event.accessTokenVerify',
          plainToClass(AuthenticationsAccessTokensPayload, tokenPayload)
        );
        return tokenPayload;
      }),
      mergeMap((tokenPayload) => this._repositoryService.getOneAccess({
        userId: tokenPayload.userId,
        accessToken: payload.accessToken,
      }).pipe(
        map(() => new AuthenticationsAccessTokensPayload(tokenPayload)),
        catchError(() => throwError(() => new AuthenticationsAccessNotFoundException()))
      ))
    );
  }

  /**
   * @description Method to listen messages with authentication payload to refresh JWT
   * access tokens.
   * On receiving request, this decode received JWT token and try to read access info from database,
   * after successfully database selection this method try get user info from "code-users" microservice.
   * After successfully collect data, generate response with all access data. 
   * @param {AuthenticationsRpcAccessTokensRefresh} payload Object with access JWT token
   * @returns {Observable<AuthenticationsRpcAccessTokens>} Decoded JWT token payload
   */
  @MessagePattern('authentications.accessTokensRefresh')
  @UseInterceptors(ClassSerializerInterceptor)
  public accessTokensRefresh(
    @Payload() payload: AuthenticationsRpcAccessTokensRefresh
  ): Observable<AuthenticationsRpcAccessTokens> {
    return this._securityService.verifyRefreshToken(payload.refreshToken).pipe(
      mergeMap((tokenPayload) => this._repositoryService.getOneAccess({
        userId: tokenPayload.userId,
        refreshToken: payload.refreshToken,
      }).pipe(
        catchError(() => throwError(() => new AuthenticationsAccessNotFoundException()))
      )),
      mergeMap((access) => this._rpcClient.send<UsersRpc, UsersRpcWhere>('users.getOne', {
        _id: access.userId,
        active: true,
        approve: true,
        accessLevel: access.accessLevel,
      }).pipe(
        catchError((err) => throwError(new HttpException(err, err.statusCode)))
      )),
      mergeMap((user) => this._securityService.generateAccessTokens({
        userId: user._id,
        accessLevel: user.accessLevel,
        domain: payload.requestDomain,
      }).pipe(map((accessTokens) => ({ user, accessTokens })))),
      mergeMap(({ user, accessTokens }) => this._repositoryService.createOneAccess({
        userId: user._id,
        domain: payload.requestDomain,
        accessLevel: user.accessLevel,
        accessToken: accessTokens.accessToken,
        refreshToken: accessTokens.refreshToken,
      })),
      map((access) => new AuthenticationsRpcAccessTokens({
        accessToken: access.accessToken,
        accessTokenConfig: {
          maxAge: environment.security.accessTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        },
        refreshToken: access.refreshToken,
        refreshTokenConfig: {
          maxAge: environment.security.refreshTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        },
        userPayload: {
          userId: access.userId,
          accessLevel: access.accessLevel,
          domain: access.domain,
        },
      }))
    );
  }

  /**
   * @description Method to listen event emitted after user deleted.
   * On receiving event, this method call all methods to remove all documents attached
   * to deleted user using userId like a selector for documents to delete.
   * @param {UsersRpc} payload Object with user data  
   * @private
   */
  @EventPattern('users.event.deleteOne')
  private _usersEventDeleteOne(
    @Payload() payload: UsersRpc
  ): void {
    from([
      this._repositoryService.deleteManyAccess({ userId: payload._id }).pipe(catchError(() => of())),
      this._repositoryService.deleteManyApprove({ userId: payload._id }).pipe(catchError(() => of())),
      this._repositoryService.deleteManyForgot({ userId: payload._id }).pipe(catchError(() => of())),
    ]).subscribe(
      () => null,
      () => null,
      () => this._cacheService.reset()
    );
  }
}
