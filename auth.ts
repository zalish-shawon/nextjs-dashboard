import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { sql } from '@vercel/postgres';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import { getUser } from './app/lib/data';

// Define a schema for credentials validation
const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6), // Adjust the minimum length as needed
});

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        if (!credentials) return null;

        // Parse and validate credentials
        const parsedCredentials = credentialsSchema.safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;

          // Fetch the user by email (replace getUser with your implementation)
          const user = await getUser(email);
          if (!user) return null;

          // Compare passwords
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});
