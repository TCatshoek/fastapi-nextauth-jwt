import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"

const authOptions = {
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                username: { label: "Username", type: "text", placeholder: "name" },
                password: { label: "Password", type: "password" }
            },
            async authorize(credentials, req) {
                if (credentials) {
                    return {
                        "user": credentials.username
                    } as any
                }
                return null
            }
        })
    ],
    secret: "y0uR_SuP3r_s3cr37_$3cr3t",
    url: "http://localhost:3000"
}

const handler = NextAuth(authOptions)

export { handler as GET, handler as POST }