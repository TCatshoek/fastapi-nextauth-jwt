import withAuth from "next-auth/middleware"

export default withAuth({
    secret: "y0uR_SuP3r_s3cr37_$3cr3t"
} as any)