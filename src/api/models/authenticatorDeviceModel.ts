import {model, Schema} from 'mongoose';
import {AuthDevice} from '../../types/PasskeyTypes';

const AuthenticatorDeviceSchema = new Schema<AuthDevice>({
  // TODO: add email (String, required, unique)
  // TODO: add credentialID (String, required)
  // TODO: add credentialPublicKey (Buffer, required)
  // TODO: add counter (Number, required)
  // TODO: add transports (Array of Strings, required)
});

export default model<AuthDevice>(
  'AuthenticatorDevice',
  AuthenticatorDeviceSchema,
);
