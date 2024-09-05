import {model, Schema} from 'mongoose';
import {PasskeyUserPost} from '../../types/PasskeyTypes';

const PasskeyUserSchema = new Schema<PasskeyUserPost>({
  // TODO: add userId (Number, required, unique)
  // TODO: add email (String, required, unique)
  // TODO: add devices (Array of ObjectIds, required, ref: 'AuthenticatorDevice')
});

export default model<PasskeyUserPost>('PasskeyUser', PasskeyUserSchema);
