// app/api/auth/[...nextauth]/route.ts
export const runtime = "nodejs";

import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import NextAuth, { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

const globalForPrisma = global as unknown as { prisma: PrismaClient };
const prisma = globalForPrisma.prisma || new PrismaClient();
if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;

        const member = await prisma.team.findUnique({
          where: { email: credentials.email },
          // se quiser otimizar: select apenas colunas usadas
        });
        if (!member || !member.password) return null;
        if (member.accessStatus !== "approved") {
          // dispare um erro customizado para tratar no front
          throw new Error("PENDING_REVIEW");
        }
        const stored = member.password;
        const isHash = stored.startsWith("$2");
        const ok = isHash
          ? await bcrypt.compare(credentials.password, stored)
          : credentials.password === stored;
        if (!ok) return null;

        // ⬇️ coloque o avatar do banco no campo padrão "image"
        return {
          id: member.id,
          name: member.name,
          email: member.email,
          role: member.position,
          image: member.avatarUrl ?? null,
        };
      },
    }),
  ],
  session: { strategy: "jwt" },
  callbacks: {
    async jwt({ token, user }) {
      // login inicial: copiar do user
      if (user) {
        token.id = (user as any).id;
        token.role = (user as any).role;
        // NextAuth usa "picture" internamente; manter coerente
        token.picture = (user as any).image ?? null;
      }

      // garantir que o avatar/role reflitam o banco (ex.: após upload)
      if (token?.email) {
        const member = await prisma.team.findUnique({
          where: { email: token.email as string },
          select: { id: true, position: true, avatarUrl: true },
        });
        if (member) {
          token.id = member.id;
          token.role = member.position;
          token.picture = member.avatarUrl ?? null;
        }
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = String(token.id || "");
        session.user.role = (token.role as string) || "";
        // espelhar o avatar no campo padrão
        session.user.image =
          (token.picture as string | null) ?? session.user.image ?? null;
      }
      return session;
    },
  },
  pages: { signIn: "/login" },
  secret: process.env.NEXTAUTH_SECRET,
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };
