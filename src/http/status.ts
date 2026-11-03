import { StatusCodes } from 'http-status-codes';

/** Whether a status says the request was refused, as opposed to answered. */
export const refusal = (status: number): boolean => status >= StatusCodes.BAD_REQUEST;
