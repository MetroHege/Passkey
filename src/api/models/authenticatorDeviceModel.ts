import {model, Schema} from 'mongoose';
import {AuthDevice} from '../../types/PasskeyTypes';

const AuthenticatorDeviceSchema = new Schema<AuthDevice>({
  // add email (String, required, unique)
  email: {type: String, required: true, unique: true},
  // add credentialID (String, required)
  credentialID: {type: String, required: true},
  // add credentialPublicKey (Buffer, required)
  credentialPublicKey: {type: Buffer, required: true},
  // add counter (Number, required)
  counter: {type: Number, required: true},
  // add transports (Array of Strings, required)
  transports: {type: [String], required: true},
});

export default model<AuthDevice>(
  'AuthenticatorDevice',
  AuthenticatorDeviceSchema,
);
