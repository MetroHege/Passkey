import {UserResponse} from '@sharedTypes/MessageTypes';
// TODO: add imports
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {User} from '@sharedTypes/DBTypes';
import {PublicKeyCredentialCreationOptionsJSON} from '@simplewebauthn/types';
import fetchData from '../../utils/fetchData';
import {generateRegistrationOptions} from '@simplewebauthn/server';
import {Challenge} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';

// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {
  //NODE_ENV,
  RP_ID,
  // AUTH_URL,
  //JWT_SECRET,
  RP_NAME,
} = process.env;

// Registration handler
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{
    email: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>,
  next: NextFunction,
) => {
  try {
    // Register user with AUTH API
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const UserResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );

    if (!UserResponse) {
      next(new CustomError('User not created', 400));
      return;
    }

    // Generate registration options
    const regOptions = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: UserResponse.user.username,
      attestationType: 'none',
      timeout: 60000,
      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // Save challenge to DB
    const challenge: Challenge = {
      email: UserResponse.user.email,
      challenge: regOptions.challenge,
    };

    await new challengeModel(challenge).save();

    // Add user to PasskeyUser collection
    await new passkeyUserModel({
      email: UserResponse.user.email,
      userId: UserResponse.user.user_id,
      devices: [],
    }).save();

    // Send response with email and options
    res.json({
      email: UserResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};
/*
// Registration verification handler
const verifyPasskey = async (req, res, next) => {
  try {
    // TODO: Retrieve expected challenge from DB
    // TODO: Verify registration response
    // TODO: Check if device is already registered
    // TODO: Save new authenticator to AuthenticatorDevice collection
    // TODO: Update user devices array in DB
    // TODO: Clear challenge from DB after successful registration
    // TODO: Retrieve and send user details from AUTH API
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (req, res, next) => {
  try {
    // TODO: Retrieve user and associated devices from DB
    // TODO: Generate authentication options
    // TODO: Save challenge to DB
    // TODO: Send options in response
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (req, res, next) => {
  try {
    // TODO: Retrieve expected challenge from DB
    // TODO: Verify authentication response
    // TODO: Update authenticator's counter
    // TODO: Clear challenge from DB after successful authentication
    // TODO: Generate and send JWT token
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};
*/

export {
  setupPasskey,
  // verifyPasskey,
  // authenticationOptions,
  // verifyAuthentication,
};
