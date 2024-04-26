import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"

export const { auth, handlers, signIn, signOut } = NextAuth({
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                username: {label: "Username", type: "text", placeholder: "jsmith"},
                password: {label: "Password", type: "password"}
            },
            async authorize(credentials, req) {
                if (credentials) {
                    return {id: "1", name: credentials.username, email: "test@test.nl"}
                }
                // Return null if user data could not be retrieved
                return null
            }
        })
    ],
    secret: "y0uR_SuP3r_s3cr37_$3cr3t",
})
