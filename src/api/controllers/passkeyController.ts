import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {User, UserWithLevel, UserWithNoPassword} from '@sharedTypes/DBTypes';
import {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import fetchData from '../../utils/fetchData';
import {
  generateAuthenticationOptions,
  GenerateAuthenticationOptionsOpts,
  generateRegistrationOptions,
  GenerateRegistrationOptionsOpts,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {Challenge, PasskeyUserGet} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';
import jwt from 'jsonwebtoken';

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

const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;

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

// Registration verification handler
const verifyPasskey = async (
  req: Request<
    {},
    {},
    {email: string; registrationOptions: RegistrationResponseJSON}
  >,
  res: Response<UserResponse>,
  next: NextFunction,
) => {
  try {
    // Retrieve expected challenge from DB
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });

    if (!expectedChallenge) {
      next(new CustomError('Challenge not found', 400));
      return;
    }

    // Verify registration response
    const opts: VerifyRegistrationResponseOpts = {
      response: req.body.registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      expectedRPID: RP_ID,
    };

    const verification = await verifyRegistrationResponse(opts);

    const {verified, registrationInfo} = verification;

    if (!verified || !registrationInfo) {
      next(new CustomError('Verification failed', 400));
      return;
    }

    const {credentialPublicKey, credentialID, counter} = registrationInfo;

    // Check if device is already registered
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });

    if (existingDevice) {
      next(new CustomError('Device already registered', 400));
      return;
    }

    // Save new authenticator to AuthenticatorDevice collection
    const newDevice = new authenticatorDeviceModel({
      email: req.body.email,
      credentialID,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      counter,
      transports: req.body.registrationOptions.response.transports,
    });

    const newDeviceResult = await newDevice.save();

    // Update user devices array in DB
    const user = await passkeyUserModel.findOne({email: req.body.email});

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    user.devices.push(newDeviceResult._id);
    await user.save();

    // Clear challenge from DB after successful registration
    await challengeModel.findOneAndDelete({email: req.body.email});

    // Retrieve and send user details from AUTH API
    const response = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );
    res.json(response);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request<{}, {}, {email: string}>,
  res: Response<PublicKeyCredentialRequestOptionsJSON>,
  next: NextFunction,
) => {
  try {
    // Retrieve user and associated devices from DB
    const user = (await passkeyUserModel
      .findOne({
        email: req.body.email,
      })
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    // Generate authentication options
    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      rpID: RP_ID,
      allowCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: device.transports,
      })),
      userVerification: 'preferred',
    };

    const authOptions = await generateAuthenticationOptions(opts);

    // Save challenge to DB
    await new challengeModel({
      email: req.body.email,
      challenge: authOptions.challenge,
    }).save();

    // Send options in response
    res.send(authOptions);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request<
    {},
    {},
    {email: string; authResponse: AuthenticationResponseJSON}
  >,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  try {
    // Retrieve expected challenge from DB
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });

    if (!expectedChallenge) {
      next(new CustomError('Challenge not found', 400));
      return;
    }

    const user = (await passkeyUserModel
      .findOne({email: req.body.email})
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    // Verify authentication response
    const opts: VerifyAuthenticationResponseOpts = {
      response: req.body.authResponse,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      expectedRPID: RP_ID,
      authenticator: {
        credentialPublicKey: Buffer.from(user.devices[0].credentialPublicKey),
        credentialID: user.devices[0].credentialID,
        counter: user.devices[0].counter,
      },
      requireUserVerification: false,
    };

    const verification = await verifyAuthenticationResponse(opts);

    const {verified, authenticationInfo} = verification;

    if (!verified) {
      await authenticationInfo.newCounter;
      const authenticator = authenticatorDeviceModel.findByIdAndUpdate(
        user.devices[0]._id,
        user.devices[0],
      );
    }

    // Clear challenge from DB after successful authentication
    await challengeModel.findOneAndDelete({email: req.body.email});

    // Generate and send JWT token
    const userResponse = await fetchData<UserWithNoPassword>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );

    if (!userResponse) {
      next(new CustomError('User not found', 404));
      return;
    }

    console.log(userResponse);

    const token = jwt.sign(
      {
        user_id: userResponse.user_id,
        level_name: userResponse.level_name,
      },
      JWT_SECRET,
    );

    const message: LoginResponse = {
      message: 'Login successful',
      token,
      user: userResponse,
    };

    res.json(message);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};
