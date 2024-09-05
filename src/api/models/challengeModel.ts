import {model, Schema} from 'mongoose';
import {Challenge} from '../../types/PasskeyTypes';

const challengeSchema = new Schema<Challenge>({
  // TODO: add challenge (String, required)
  // TODO: add email (String, required, unique)
});

export default model<Challenge>('Challenge', challengeSchema);
