import {
  Body,
  ClassSerializerInterceptor, Controller, HttpException,
  Inject, Post,
  RequestTimeoutException,
  Res, UseInterceptors
} from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import {
  AuthenticationsHttpV1AdminAccessResponse,
  AuthenticationsHttpV1AdminApprove,
  AuthenticationsHttpV1AdminApproveRefresh,
  AuthenticationsHttpV1AdminForgot,
  AuthenticationsHttpV1AdminForgotPassword,
  AuthenticationsHttpV1AdminSignIn,
  AuthenticationsHttpV1AdminSignUp
} from '@zozoboom/core-authentications/backend/dto';
import {
  AuthenticationsAccessNotApprovedException,
  AuthenticationsApproveAlearyApprovedException,
  AuthenticationsApproveConflictException,
  AuthenticationsForgotConflictException
} from '@zozoboom/core-authentications/backend/exception';
import {
  NotificationsApprovePayload,
  NotificationsForgotPayload
} from '@zozoboom/core-notifications/backend/dto';
import {
  UsersHttpV1Admin,
  UsersRpc, UsersRpcCreate, UsersRpcUpdateOne,
  UsersRpcWhere
} from '@zozoboom/core-users/backend/dto';
import {
  UsersAccessLevelEnum,
  UsersErrorsEnum
} from '@zozoboom/core-users/common/enum';
import { RequestDomain } from '@zozoboom/core/backend/decorator';
import { LocaleEnum } from '@zozoboom/core/common/enum';
import { FastifyReply } from 'fastify';
import { Observable, of, throwError, TimeoutError } from 'rxjs';
import { catchError, map, mergeMap, timeout } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { RepositoryService } from '../repository.service';
import { SecurityService } from '../security.service';

@Controller('admin/v1')
export class AdminV1Controller {
  constructor(
    @Inject('RPC_SERVICE') private readonly _rpcClient: ClientProxy,
    private readonly _repositoryService: RepositoryService,
    private readonly _securityService: SecurityService
  ) { }

  /**
   * @description Method used to signUp new user. This method call "code-users" microservice to
   * send message to create new user with provided data, after method generate a random approve code
   * and emit event listened by "code-notifications" to send email notification, to
   * "super admin" email provided on ENV param, with approve code.
   * @param {AuthenticationsHttpV1AdminSignUp} body Object with authentication data for signUp
   * @returns {Observable<Partial<UsersHttpV1Admin>>} Base info about created user
   */
  @Post('sign-up')
  @UseInterceptors(ClassSerializerInterceptor)
  public signUp(
    @Body() body: AuthenticationsHttpV1AdminSignUp
  ): Observable<Partial<UsersHttpV1Admin>> {
    return this._securityService.encryptPassword(body.password).pipe(
      mergeMap((password) => this._rpcClient.send<UsersRpc, UsersRpcCreate>('users.createOne', {
        ...body,
        ...{ password, accessLevel: UsersAccessLevelEnum.ADMIN },
      }).pipe(
        timeout(5000),
        catchError((err) => {
          if (err instanceof TimeoutError)
            // TODO: Fix this HTTP error to userCustomException
            throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
          return throwError(() => new HttpException(err, err.statusCode));
        })
      )),
      mergeMap((user) => this._securityService.generateApproveCode().pipe(
        map((code) => ({ user, code }))
      )),
      mergeMap(({ user, code }) => this._repositoryService.createOneApprove({
        userId: user._id,
        email: user.email,
        code: code,
      }).pipe(
        map((approve) => ({ user, approve })),
        catchError((err) => {
          if (err instanceof AuthenticationsApproveConflictException)
            return this._repositoryService.getOneApprove({ userId: user._id }).pipe(
              map((approve) => ({ user, approve }))
            );
        }),
      )),
      mergeMap(({ user, approve }) => this._rpcClient.emit<void, NotificationsApprovePayload>(
        'notifications.emailApprove',
        {
          userId: user._id,
          email: environment.security.emailAdminApprove,
          locale: LocaleEnum.RU,
          firstName: user.firstName,
          lastName: user.lastName,
          code: approve.code,
        }
      ).pipe(
        map(() => ({ user }))
      )),
      map(({ user }) => new UsersHttpV1Admin({
        _id: user._id,
        accessLevel: user.accessLevel,
      }))
    );
  }

  /**
   * @description Method used to signIn existent user. This method first call "core-users" microservice,
   * to check if target user exist and provided password is ok.
   * After check if user is ready for authentication, we generate access tokens and save created tokens to database,
   * tokens are written to cookie and returning  authentication data in response.
   * @param {string} requestDomain Domain where the request came from
   * @param {FastifyReply} response Request response object 
   * @param {AuthenticationsHttpV1AdminSignIn} body Object with authentication data for signIn
   * @returns {Observable<AuthenticationsHttpV1AdminAccessResponse>} Object with authentication data
   */
  @Post('sign-in')
  @UseInterceptors(ClassSerializerInterceptor)
  public signIn(
    @RequestDomain() requestDomain: string,
    @Res({ passthrough: true }) response: FastifyReply,
    @Body() body: AuthenticationsHttpV1AdminSignIn
  ): Observable<AuthenticationsHttpV1AdminAccessResponse> {
    return this._rpcClient.send<UsersRpc, UsersRpcWhere>('users.getOne', {
      email: body.email,
      active: true,
      accessLevel: UsersAccessLevelEnum.ADMIN,
    }).pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError)
          // TODO: Fix this HTTP error to userCustomException
          throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
        return throwError(() => new HttpException(err, err.statusCode));
      }),
      map((user) => {
        if (!user.approve)
          throw new AuthenticationsAccessNotApprovedException();
        return user;
      }),
      mergeMap((user) => this._securityService.checkPassword(body.password, user.password).pipe(
        map(() => user)
      )),
      mergeMap((user) => this._securityService.generateAccessTokens({
        userId: user._id,
        accessLevel: user.accessLevel,
        domain: requestDomain,
      }).pipe(
        map((accessTokens) => ({ user, accessTokens }))
      )),
      mergeMap(({ user, accessTokens }) => this._repositoryService.createOneAccess({
        userId: user._id,
        domain: requestDomain,
        accessLevel: user.accessLevel,
        accessToken: accessTokens.accessToken,
        refreshToken: accessTokens.refreshToken,
      }).pipe(
        map((access) => ({ user, access }))
      )),
      map(({ user, access }) => {
        this._rpcClient.emit<void, UsersRpc>('authentications.event.signIn', new UsersRpc(user));
        return { user, access };
      }),
      map(({ user, access }) => {
        response.setCookie('accessToken', access.accessToken, {
          maxAge: environment.security.accessTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        });
        response.setCookie('refreshToken', access.refreshToken, {
          maxAge: environment.security.refreshTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        });
        return new AuthenticationsHttpV1AdminAccessResponse({
          accessTokens: access,
          user: user,
        });
      })
    );
  }

  /**
   * @description Method used to approve signUp. This method first call "core-users" microservice,
   * to check if target user exist and not already approved.
   * After check if user is allowed to approve, we check if provided approve code is same like
   * attached to target user and if all is ok, approve is deleted from database and we
   * send message to "core-users" microservice to set user like approve after 
   * we generate access tokens and save created tokens to database,
   * tokens are written to cookie and returning  authentication data in response.
   * @param {string} requestDomain Domain where the request came from
   * @param {FastifyReply} response Request response object 
   * @param {AuthenticationsHttpV1AdminApprove} body Object with authentication data for approve 
   * @returns {Observable<AuthenticationsHttpV1AdminAccessResponse>} Object with authentication data
   */
  @Post('approve')
  @UseInterceptors(ClassSerializerInterceptor)
  public approve(
    @RequestDomain() requestDomain: string,
    @Res({ passthrough: true }) response: FastifyReply,
    @Body() body: AuthenticationsHttpV1AdminApprove
  ): Observable<AuthenticationsHttpV1AdminAccessResponse> {
    return this._rpcClient.send<UsersRpc, UsersRpcWhere>('users.getOne', {
      email: body.email,
      active: true,
      accessLevel: UsersAccessLevelEnum.ADMIN,
    }).pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError)
          // TODO: Fix this HTTP error to userCustomException
          throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
        return throwError(() => new HttpException(err, err.statusCode));
      }),
      map((user) => {
        if (user.approve)
          throw new AuthenticationsApproveAlearyApprovedException();
        return user;
      }),
      mergeMap((user) => this._repositoryService.getOneApprove({
        userId: user._id,
        email: user.email,
        code: body.code,
      }).pipe(
        map(() => user)
      )),
      mergeMap((user) => this._repositoryService.deleteManyApprove({
        userId: user._id,
        email: user.email,
      }).pipe(
        map(() => user),
        catchError(() => of(user))
      )),
      mergeMap((user) => this._rpcClient.send<UsersRpc, UsersRpcUpdateOne>('users.updateOne', {
        where: { _id: user._id, email: user.email },
        data: { approve: true },
      }).pipe(
        timeout(5000),
        map(() => user),
        catchError((err) => {
          if (err instanceof TimeoutError)
            // TODO: Fix this HTTP error to userCustomException
            throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
          return throwError(() => new HttpException(err, err.statusCode));
        }),
      )),
      mergeMap((user) => this._securityService.generateAccessTokens({
        userId: user._id,
        accessLevel: user.accessLevel,
        domain: requestDomain,
      }).pipe(
        map((accessTokens) => ({ user, accessTokens }))
      )),
      mergeMap(({ user, accessTokens }) => this._repositoryService.createOneAccess({
        userId: user._id,
        domain: requestDomain,
        accessLevel: user.accessLevel,
        accessToken: accessTokens.accessToken,
        refreshToken: accessTokens.refreshToken,
      }).pipe(
        map((access) => ({ user, access }))
      )),
      map(({ user, access }) => {
        this._rpcClient.emit<void, UsersRpc>('authentications.event.signIn', new UsersRpc(user));
        response.setCookie('accessToken', access.accessToken, {
          maxAge: environment.security.accessTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        });
        response.setCookie('refreshToken', access.refreshToken, {
          maxAge: environment.security.refreshTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        });
        return new AuthenticationsHttpV1AdminAccessResponse({
          accessTokens: access,
          user: user,
        });
      })
    );
  }

  /**
   * @description Method used to refresh approve code. This method first call "core-users" microservice,
   * to check if target user exist and not already approved.
   * After check if user is allowed to fetch again approve info, we generate new or use existent approve info
   * and emit event listened by "code-notifications" to send email notification, to
   * "super admin" email provided on ENV param, with approve code.
   * @param {AuthenticationsHttpV1AdminApproveRefresh} body Object with info about approve refresh receiver
   * @returns {Observable<Partial<UsersHttpV1Admin>>} Object with authentication data
   */
  @Post('approve-refresh')
  @UseInterceptors(ClassSerializerInterceptor)
  public approveRefresh(
    @Body() body: AuthenticationsHttpV1AdminApproveRefresh
  ): Observable<Partial<UsersHttpV1Admin>> {
    return this._rpcClient.send<UsersRpc, UsersRpcWhere>('users.getOne', {
      email: body.email,
      active: true,
      approve: false,
      accessLevel: UsersAccessLevelEnum.ADMIN,
    }).pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError)
          // TODO: Fix this HTTP error to userCustomException
          throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
        return throwError(() => new HttpException(err, err.statusCode));
      }),
      map((user) => {
        if (user.approve)
          throw new AuthenticationsApproveAlearyApprovedException();
        return user;
      }),
      mergeMap((user) => this._securityService.generateApproveCode().pipe(
        map((code) => ({ user, code }))
      )),
      mergeMap(({ user, code }) => this._repositoryService.createOneApprove({
        userId: user._id,
        email: user.email,
        code: code,
      }).pipe(
        map((approve) => ({ user, approve })),
        catchError((err) => {
          if (err instanceof AuthenticationsApproveConflictException)
            return this._repositoryService.getOneApprove({ userId: user._id }).pipe(
              map((approve) => ({ user, approve }))
            );
        }),
      )),
      mergeMap(({ user, approve }) => this._rpcClient.emit<void, NotificationsApprovePayload>(
        'notifications.emailApprove',
        {
          userId: user._id,
          email: environment.security.emailAdminApprove,
          locale: LocaleEnum.RU,
          firstName: user.firstName,
          lastName: user.lastName,
          code: approve.code,
        }
      ).pipe(
        map(() => ({ user }))
      )),
      map(({ user }) => new UsersHttpV1Admin({
        _id: user._id,
        accessLevel: user.accessLevel,
      }))
    );
  }

  /**
   * @description Method used to init forgot password action. This method first call "core-users" microservice,
   * to check if target user exist ready for forgot.
   * After check if user is ready for authentication, we generate forgot tokens and save created tokens to database,
   * and emit event listened by "code-notifications" to send email notification with forgot info.
   * @param {AuthenticationsHttpV1AdminForgot} body Object with info about forgot receiver
   * @returns {Observable<Partial<UsersHttpV1Admin>>} Base info about created user
   */
  @Post('forgot')
  @UseInterceptors(ClassSerializerInterceptor)
  public forgot(
    @Body() body: AuthenticationsHttpV1AdminForgot
  ): Observable<Partial<UsersHttpV1Admin>> {
    return this._rpcClient.send<UsersRpc, UsersRpcWhere>('users.getOne', {
      email: body.email,
      active: true,
      accessLevel: UsersAccessLevelEnum.ADMIN,
    }).pipe(
      timeout(5000),
      catchError((err) => {
        if (err instanceof TimeoutError)
          // TODO: Fix this HTTP error to userCustomException
          throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
        return throwError(() => new HttpException(err, err.statusCode));
      }),
      map((user) => {
        if (!user.approve)
          throw new AuthenticationsAccessNotApprovedException();
        return user;
      }),
      mergeMap((user) => this._securityService.generateForgotToken(user._id).pipe(
        map((forgotToken) => ({ user, forgotToken }))
      )),
      mergeMap(({ user, forgotToken }) => this._repositoryService.createOneForgot({
        userId: user._id,
        email: user.email,
        token: forgotToken,
      }).pipe(
        map((forgot) => ({ user, forgot })),
        catchError((err) => {
          if (err instanceof AuthenticationsForgotConflictException)
            return this._repositoryService.getOneForgot({ userId: user._id }).pipe(
              map((forgot) => ({ user, forgot }))
            );
        }),
      )),
      mergeMap(({ user, forgot }) => this._rpcClient.emit<void, NotificationsForgotPayload>(
        'notifications.emailForgot',
        {
          userId: user._id,
          email: user.email,
          locale: LocaleEnum.RU,
          firstName: user.firstName,
          lastName: user.lastName,
          token: forgot.token,
          backLink: body.backLink,
        }
      ).pipe(
        map(() => ({ user }))
      )),
      map(({ user }) => new UsersHttpV1Admin({
        _id: user._id,
        accessLevel: user.accessLevel,
      }))
    );
  }

  /**
   * @description Method used to forgot password. This method first check if forgot JWT token is valid,
   * after call "core-users" microservice to check if target user exist.
   * After check if user is ready for forgot password, we generate access tokens and save created tokens to database,
   * tokens are written to cookie and returning  authentication data in response.
   * @param {string} requestDomain Domain where the request came from
   * @param {FastifyReply} response Request response object
   * @param {AuthenticationsHttpV1AdminApprove} body Object with authentication data for approve
   * @returns {Observable<AuthenticationsHttpV1AdminAccessResponse>} Object with authentication data
   */
  @Post('forgot-password')
  @UseInterceptors(ClassSerializerInterceptor)
  public forgotPassword(
    @RequestDomain() requestDomain: string,
    @Res({ passthrough: true }) response: FastifyReply,
    @Body() body: AuthenticationsHttpV1AdminForgotPassword
  ): Observable<AuthenticationsHttpV1AdminAccessResponse> {
    return this._securityService.verifyForgotToken(body.token).pipe(
      mergeMap((tokenPayload) => this._repositoryService.getOneForgot({
        userId: tokenPayload.userId,
        token: body.token,
      })),
      mergeMap((forgot) => this._rpcClient.send<UsersRpc, UsersRpcWhere>(
        'users.getOne',
        {
          _id: forgot.userId,
          active: true,
          approve: true,
          accessLevel: UsersAccessLevelEnum.ADMIN,
        }
      ).pipe(
        timeout(5000),
        catchError((err) => {
          if (err instanceof TimeoutError)
            // TODO: Fix this HTTP error to userCustomException
            throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
          return throwError(() => new HttpException(err, err.statusCode));
        }),
      )),
      mergeMap((user) => this._securityService.encryptPassword(body.password).pipe(
        map((password) => ({ user, password }))
      )),
      mergeMap(({ user, password }) => this._rpcClient.send<UsersRpc, UsersRpcUpdateOne>(
        'users.updateOne',
        {
          where: { _id: user._id, email: user.email },
          data: { password },
        }
      ).pipe(
        timeout(5000),
        catchError((err) => {
          if (err instanceof TimeoutError)
            // TODO: Fix this HTTP error to userCustomException
            throw new RequestTimeoutException(UsersErrorsEnum.EXECUTION_TIMEOUT);
          return throwError(() => new HttpException(err, err.statusCode));
        }),
        map(() => user)
      )),
      mergeMap((user) => this._repositoryService.deleteManyForgot({
        userId: user._id,
        email: user.email,
      }).pipe(
        map(() => user),
        catchError(() => of(user))
      )),
      mergeMap((user) => this._securityService.generateAccessTokens({
        userId: user._id,
        accessLevel: user.accessLevel,
        domain: requestDomain,
      }).pipe(
        map((accessTokens) => ({ user, accessTokens }))
      )),
      mergeMap(({ user, accessTokens }) => this._repositoryService.createOneAccess({
        userId: user._id,
        domain: requestDomain,
        accessLevel: user.accessLevel,
        accessToken: accessTokens.accessToken,
        refreshToken: accessTokens.refreshToken,
      }).pipe(
        map((access) => ({ user, access }))
      )),
      map(({ user, access }) => {
        this._rpcClient.emit<void, UsersRpc>('authentications.event.signIn', new UsersRpc(user));
        return { user, access };
      }),
      map(({ user, access }) => {
        response.setCookie('accessToken', access.accessToken, {
          maxAge: environment.security.accessTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        });
        response.setCookie('refreshToken', access.refreshToken, {
          maxAge: environment.security.refreshTokenTTL,
          httpOnly: true,
          secure: false,
          sameSite: true,
          path: '/',
        });
        return new AuthenticationsHttpV1AdminAccessResponse({
          accessTokens: access,
          user: user,
        });
      })
    );
  }
}
