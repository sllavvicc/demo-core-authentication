import { Controller } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { from } from 'rxjs';
import { RepositoryService } from './repository.service';

@Controller()
export class CronController {
  constructor(private readonly _repositoryService: RepositoryService) { }

  /**
   * @description Method used to clean up authentication data,
   * on database. This method running each 15 min.
   * This method remove unused access and forgot. 
   * @private
   */
  @Cron('* */15 * * * *')
  private _cleanUpAccessAndForgot(): void {
    from([
      this._repositoryService.cleanUpAccess(),
      this._repositoryService.cleanUpForgot(),
    ]).subscribe(
      () => null,
      () => null,
      () => null
    );
  }
}
