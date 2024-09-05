// TODO: add imports
import CustomError from '../../classes/CustomError';

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
const setupPasskey = async (req, res, next) => {
  try {
    // TODO: Register user with AUTH API
    // TODO: Generate registration options
    // TODO: Save challenge to DB
    // TODO: Add user to PasskeyUser collection
    // TODO: Send response with email and options
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

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

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};
