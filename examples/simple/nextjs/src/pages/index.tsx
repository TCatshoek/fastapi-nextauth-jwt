import {Inter} from 'next/font/google'
import {getCsrfToken, useSession} from "next-auth/react";
import {useState} from "react";

const inter = Inter({subsets: ['latin']})

const buttonStyles = "bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-full"

export default function Home() {
    const [response, setResponse] = useState<string | undefined>();

    const buttonHandler = async () => {
        try {
            // Normally you'd use GET here, but we want to show how to do CSRF protection too,
            // Which with the default configuration doesn't happen on GET requests
            const csrfToken = await getCsrfToken()

            if (!csrfToken) {
                throw new Error("No csrf token")
            }

            const res = await fetch("fastapi/", {
                method: "POST",
                headers: {
                    "X-XSRF-Token": csrfToken
                }
            })
            const res_json = await res.json()
            setResponse(res_json.message)
        } catch (e) {
            setResponse("error")
        }
    }

    const {data: session} = useSession({
        required: true,
    })

    return (
        <main
            className={`flex min-h-screen flex-col items-center justify-between p-24 ${inter.className}`}
        >
            <div className="flex flex-col items-center gap-2">
                Hello {session?.user?.name}
                <button className={buttonStyles} onClick={buttonHandler}>
                    Talk to FastAPI!
                </button>
                {response ? <pre> {response} </pre> : null}
            </div>
        </main>
    )
}
