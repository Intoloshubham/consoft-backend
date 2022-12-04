import { ObjectId } from "mongodb";
import mongoose from "mongoose";

const forgetPasswordSchema = mongoose.Schema({
    user_id: {type: ObjectId, required: true},
    otp:{type:String,required:true},
    email:{type:String,required:true}
},{ timestamps: true });

export default mongoose.model('ForgetPassword', forgetPasswordSchema);