import {model, Schema, Types} from 'mongoose';
import {PasskeyUserPost} from '../../types/PasskeyTypes';

const PasskeyUserSchema = new Schema<PasskeyUserPost>({
  // add userId (Number, required, unique)
  userId: {type: Number, required: true, unique: true},
  // add email (String, required, unique)
  email: {type: String, required: true, unique: true},
  // add devices (Array of ObjectIds, required, ref: 'AuthenticatorDevice')
  devices: {type: [Types.ObjectId], required: true, ref: 'AuthenticatorDevice'},
});

export default model<PasskeyUserPost>('PasskeyUser', PasskeyUserSchema);
