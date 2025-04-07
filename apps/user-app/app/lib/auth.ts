import db from '@repo/db/client';
import CredentialProvider from 'next-auth/providers/credentials';
import bcrypt from "bcrypt";
import { AuthOptions } from 'next-auth';

export const authOptions : AuthOptions = {
    providers : [
        CredentialProvider({
            name : "Credentials",
            credentials : {
                phone : {label : "Phone number", type : "text", placeholder : "1234567890"},
                password : {label : "Password", type : "password", placeholder : "Enter password"}
            },
            async authorize(credentials : any){
                const hashedPassword = await bcrypt.hash(credentials.password, 10);
                
                const isExistingUser = await db.user.findFirst({
                    where : {
                        number : credentials.phone
                    }
                })

                if(isExistingUser){
                    const passwordValidation = await bcrypt.compare(credentials.password, isExistingUser.password);
                    if(passwordValidation){
                        return {
                            id : isExistingUser.id.toString(),
                            name : isExistingUser.name,
                            email : isExistingUser.email
                        }
                    }
                    return null;
                }

                try{
                    const user = await db.user.create({
                        data : {
                            number : credentials.phone,
                            password : credentials.password
                        }
                    })

                    return {
                        id : user.id.toString(),
                        name : user.name,
                        email : user.email
                    }
                }catch(err){    
                    console.log("error creating new user : ", err);
                }

                return null;
            }
        })
    ],

    secret : process.env.NEXTAUTH_SECRET || "secret",

    callbacks : {
        async session ({token, session} : any){
            session.user.id = token.sub
            return session
        }
    }
}
