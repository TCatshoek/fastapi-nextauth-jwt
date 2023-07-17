import NextAuth from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"

export const authOptions = {
    providers: [
        CredentialsProvider({
            name: 'Credentials',
            credentials: {
                username: {label: "Username", type: "text", placeholder: "jsmith"},
                password: {label: "Password", type: "password"}
            },
            async authorize(credentials, req) {
                if (credentials) {
                    return {id: 1, name: credentials.username, email: "test@test.nl"}
                }
                // Return null if user data could not be retrieved
                return null
            }
        })
    ],
    secret: "y0uR_SuP3r_s3cr37_$3cr3t",
    // callbacks: {
    //     // async jwt({ token, account, profile }) {
    //     async jwt({ token, account, profile }) {
    //         console.log("token", token)
    //         console.log("account", account)
    //         console.log("profile", profile)
    //         // Persist the OAuth access_token and or the user id to the token right after signin
    //         if (account) {
    //             token.accessToken = account.access_token
    //             token.id = profile.id
    //         }
    //         return token
    //     }
    // }
}

export default NextAuth(authOptions)

