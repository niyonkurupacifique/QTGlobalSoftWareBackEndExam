import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
export const createJWT=(user)=>{
    const token=jwt.sign({
        id:user.id,
        username:user.username
         },
       process.env.JWT_SECRET
    )
   return token 
}



const protect = (req, res, next) => {
    var bearer = req.headers.authorization;
    if (!bearer) {
        res.status(401).send({ message: 'Not authorized please login first' });
        return;
    }

    const [,token] = bearer.split(' ').map(part => part.trim());
 

    if (!token) {
        res.status(401).send({errorMessage: 'signin required' });
        return;
    }

    try {
        const user = jwt.verify(token, process.env.JWT_SECRET);
        req.user = user;
        next();
    } catch (e) {
        console.error(e);
        res.status(401).send({errorMessage: 'signin required' });
        return;
    }
};

export default protect


export const comparePassword=(password,hash)=>{
    return bcrypt.compare(password,hash)

}
export const hashPassword=(password)=>{
 return bcrypt.hash(password,5)
}