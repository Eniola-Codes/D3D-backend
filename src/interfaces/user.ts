import { JwtPayload } from 'jsonwebtoken';

export interface isAuthPayload extends JwtPayload {
  id: string;
  email: string;
}
