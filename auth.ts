import NextAuth from "next-auth";
import { authConfig } from "./auth.config";
import Credentials from "next-auth/providers/credentials";
import { z } from "zod";
import { db } from "@vercel/postgres";
import type { User } from "@/app/lib/definitions";
import bcrypt from "bcrypt";

async function getUser(email: string): Promise<User | undefined> {
  const clientPromise = db.connect();
  try {
    const client = await clientPromise;
    const result =
      await client.sql<User>`SELECT * FROM users WHERE email=${email}`;
    return result.rows[0];
  } catch (error) {
    console.error("Failed to fetch user:", error);
    throw new Error("Failed to fetch user.");
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        // Validate credentials using zod schema
        const parsedCredentials = z
          .object({
            email: z.string().email(),
            password: z.string().min(6),
          })
          .safeParse(credentials);

        // Checks if credentials conform on the zod schema
        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;

          // Fetch user from database
          const user = await getUser(email);
          if (!user) return null;

          // Verify password
          const passwordMatch = await bcrypt.compare(password, user.password);
          if (passwordMatch) return user;
        }

        console.log("Invalid credentials");
        return null;
      },
    }),
  ],
});
