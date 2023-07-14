"use client";
import {useState} from "react";
import { useSession } from "next-auth/react"

const onClick = () => {

}
export default function Home() {
    const [response, setResponse] = useState();
    const {data: session} = useSession()

    return (
        <main className="flex min-h-screen flex-col items-center justify-between p-24">
            <div className="border border-red-500">
                <button className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-full">
                    Talk to FastAPI
                </button>
            </div>
        </main>
    )
}
