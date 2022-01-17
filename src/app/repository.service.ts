import { Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import {
  AuthenticationsAccess,
  AuthenticationsAccessCreate,
  AuthenticationsAccessWhere,
  AuthenticationsApprove,
  AuthenticationsApproveCreate,
  AuthenticationsApproveWhere,
  AuthenticationsForgot,
  AuthenticationsForgotCreate,
  AuthenticationsForgotWhere
} from '@zozoboom/core-authentications/backend/dto';
import {
  AuthenticationsAccessInternalServerErrorException,
  AuthenticationsAccessNotFoundException,
  AuthenticationsApproveConflictException,
  AuthenticationsApproveInternalServerErrorException,
  AuthenticationsApproveNotFoundException,
  AuthenticationsForgotConflictException,
  AuthenticationsForgotInternalServerErrorException,
  AuthenticationsForgotNotFoundException
} from '@zozoboom/core-authentications/backend/exception';
import {
  AuthenticationsAccessCollection,
  AuthenticationsApproveCollection,
  AuthenticationsForgotCollection
} from '@zozoboom/core-authentications/backend/schema';
import { MONGO_CONFLICT } from '@zozoboom/core/backend/constant';
import { Model } from 'mongoose';
import { from, Observable, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { environment } from '../environments/environment';

@Injectable()
export class RepositoryService {
  private readonly _logger: Logger = new Logger('RepositoryService');
  constructor(
    @InjectModel(AuthenticationsAccessCollection.name)
    private readonly _authenticationsAccessModel: Model<AuthenticationsAccessCollection>,
    @InjectModel(AuthenticationsApproveCollection.name)
    private readonly _authenticationsApproveModel: Model<AuthenticationsApproveCollection>,
    @InjectModel(AuthenticationsForgotCollection.name)
    private readonly _authenticationsForgotModel: Model<AuthenticationsForgotCollection>
  ) { }

  /**
   * @description Method used to fetch authentication access info from database based on
   * provided "where" object.
   * @param {AuthenticationsAccessWhere} where Object used on selection from database
   * @returns {Observable<AuthenticationsAccess>} Object with authentication access info
   */
  public getOneAccess(
    where: AuthenticationsAccessWhere
  ): Observable<AuthenticationsAccess> {
    return from(this._authenticationsAccessModel.findOne(where).exec()).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsAccessInternalServerErrorException());
      }),
      map((access) => {
        if (!access) throw new AuthenticationsAccessNotFoundException();
        return new AuthenticationsAccess(access);
      })
    );
  }

  /**
   * @description Method used to fetch authentication approve info from database based on
   * provided "where" object.
   * @param {AuthenticationsApproveWhere} where Object used on selection from database
   * @returns {Observable<AuthenticationsApprove>} Object with authentication approve info
   */
  public getOneApprove(
    where: AuthenticationsApproveWhere
  ): Observable<AuthenticationsApprove> {
    return from(this._authenticationsApproveModel.findOne(where).exec()).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsApproveInternalServerErrorException());
      }),
      map((approve) => {
        if (!approve) throw new AuthenticationsApproveNotFoundException();
        return new AuthenticationsApprove(approve);
      })
    );
  }

  /**
   * @description Method used to fetch authentication forgot info from database based on
   * provided "where" object.
   * @param {AuthenticationsForgotWhere} where Object used on selection from database
   * @returns {Observable<AuthenticationsForgot>} Object with authentication forgot info 
   */
  public getOneForgot(
    where: AuthenticationsForgotWhere
  ): Observable<AuthenticationsForgot> {
    return from(this._authenticationsForgotModel.findOne(where).exec()).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsForgotInternalServerErrorException());
      }),
      map((forgot) => {
        if (!forgot) throw new AuthenticationsForgotNotFoundException();
        return new AuthenticationsForgot(forgot);
      })
    );
  }

  /**
   * @description Method used to write authentication access info into database
   * using "data" like a payload on insert action.
   * @param {AuthenticationsAccessCreate} data Object with authentication access info to write on database
   * @returns {Observable<AuthenticationsAccess>} Object with authentication access info
   */
  public createOneAccess(
    data: AuthenticationsAccessCreate
  ): Observable<AuthenticationsAccess> {
    return from(new this._authenticationsAccessModel(data).save()).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsAccessInternalServerErrorException());
      }),
      map((access) => new AuthenticationsAccess(access))
    );
  }

  /**
   * @description Method used to write authentication approve info into database
   * using "data" like a payload on insert action.
   * @param {AuthenticationsApproveCreate} data Object with authentication approve info to write on database
   * @returns {Observable<AuthenticationsApprove>} Object with authentication approve info
   */
  public createOneApprove(
    data: AuthenticationsApproveCreate
  ): Observable<AuthenticationsApprove> {
    return from(new this._authenticationsApproveModel(data).save()).pipe(
      map((approve) => new AuthenticationsApprove(approve)),
      catchError((err) => {
        if (err.code === MONGO_CONFLICT)
          return throwError(() => new AuthenticationsApproveConflictException());
        this._logger.error(err);
        return throwError(() => new AuthenticationsApproveInternalServerErrorException());
      })
    );
  }

  /**
   * @description Method used to write authentication forgot info into database
   * using "data" like a payload on insert action.
   * @param {AuthenticationsForgotCreate} data Object with authentication forgot info to write on database
   * @returns {Observable<AuthenticationsForgot>} Object with authentication forgot info
   */
  public createOneForgot(
    data: AuthenticationsForgotCreate
  ): Observable<AuthenticationsForgot> {
    return from(new this._authenticationsForgotModel(data).save()).pipe(
      map((forgot) => new AuthenticationsForgot(forgot)),
      catchError((err) => {
        if (err.code === MONGO_CONFLICT)
          return throwError(() => new AuthenticationsForgotConflictException());
        this._logger.error(err);
        return throwError(() => new AuthenticationsForgotInternalServerErrorException());
      })
    );
  }

  /**
   * @description Method used to delete many authentication access documents from database
   * using "where" to select target documents for deleting.
   * @param {AuthenticationsAccessWhere} where Object used to select documents for deleting from database 
   * @returns {Observable<number>} Number with count of deleted documents
   */
  public deleteManyAccess(
    where: AuthenticationsAccessWhere
  ): Observable<number> {
    return from(this._authenticationsAccessModel.deleteMany(where).exec()).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsAccessInternalServerErrorException());
      }),
      map(({ deletedCount }) => {
        if (deletedCount === 0) throw new AuthenticationsAccessNotFoundException();
        return deletedCount;
      })
    );
  }

  /**
   * @description Method used to delete many authentication approve documents from database
   * using "where" to select target documents for deleting.
   * @param {AuthenticationsApproveWhere} where Object used to select documents for deleting from database 
   * @returns {Observable<number>} Number with count of deleted documents
   */
  public deleteManyApprove(
    where: AuthenticationsApproveWhere
  ): Observable<number> {
    return from(
      this._authenticationsApproveModel.deleteMany(where).exec()
    ).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsApproveInternalServerErrorException());
      }),
      map(({ deletedCount }) => {
        if (deletedCount === 0) throw new AuthenticationsApproveNotFoundException();
        return deletedCount;
      })
    );
  }

  /**
   * @description Method used to delete many authentication forgot documents from database
   * using "where" to select target documents for deleting.
   * @param {AuthenticationsApproveWhere} where Object used to select documents for deleting from database 
   * @returns {Observable<number>} Number with count of deleted documents
   */
  public deleteManyForgot(
    where: AuthenticationsForgotWhere
  ): Observable<number> {
    return from(this._authenticationsForgotModel.deleteMany(where).exec()).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsForgotInternalServerErrorException());
      }),
      map(({ deletedCount }) => {
        if (deletedCount === 0) throw new AuthenticationsForgotNotFoundException();
        return deletedCount;
      })
    );
  }

  /**
   * @description A method used to remove many unused authentication access documents from the database.
   * This method selects documents with a createdAt field below the current date
   * minus the maximum access TTL value read from the ENV parameters.
   * @returns {Observable<number>} Number with count of deleted documents
   */
  public cleanUpAccess(): Observable<number> {
    return from(
      this._authenticationsAccessModel
        .deleteMany({
          createdAt: {
            $lte: new Date(
              new Date().setSeconds(
                new Date().getSeconds() - environment.security.refreshTokenTTL
              )
            ),
          },
        })
        .exec()
    ).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsAccessInternalServerErrorException());
      }),
      map(({ deletedCount }) => {
        if (deletedCount === 0) throw new AuthenticationsAccessNotFoundException();
        return deletedCount;
      })
    );
  }

  /**
   * @description A method used to remove many unused authentication forgo documents from the database.
   * This method selects documents with a createdAt field below the current date
   * minus the maximum forgo TTL value read from the ENV parameters.
   * @returns {Observable<number>} Number with count of deleted documents
   */
  public cleanUpForgot(): Observable<number> {
    return from(
      this._authenticationsForgotModel
        .deleteMany({
          createdAt: {
            $lte: new Date(
              new Date().setSeconds(
                new Date().getSeconds() - environment.security.forgotTokenTTL
              )
            ),
          },
        })
        .exec()
    ).pipe(
      catchError((err) => {
        this._logger.error(err);
        return throwError(() => new AuthenticationsForgotInternalServerErrorException());
      }),
      map(({ deletedCount }) => {
        if (deletedCount === 0) throw new AuthenticationsForgotNotFoundException();
        return deletedCount;
      })
    );
  }
}
