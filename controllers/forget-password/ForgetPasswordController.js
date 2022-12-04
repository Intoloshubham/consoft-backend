// import { UserPrivilege } from "../../models/index.js";
import { User, ForgetPassword } from "../../models/index.js";
import CustomErrorHandler from "../../services/CustomErrorHandler.js";
import CustomFunction from "../../services/CustomFunction.js";
import CustomSuccessHandler from "../../services/CustomSuccessHandler.js";
import bcrypt from "bcrypt";
import transporter from "../../config/emailConfig.js";
import { EMAIL_FROM } from "../../config/index.js";
const ForgetPasswordController = {
  async forgetPassword(req, res, next) {
    let temp;
    const { user_id, email, otp } = req.body;
    const existMail = await User.exists({ user_id: user_id, email: email });

    if (!existMail) {
      return next(CustomSuccessHandler.customMessage("Email does not exist"));
    }

    const temp_otp = await CustomFunction.randomNumber();
    const hashOtp = await bcrypt.hash(temp_otp.toString(), 10);

    // const exist = await ForgetPassword.exists({
    //   user_id: user_id,
    //   email: email,
    // });
    const forget = new ForgetPassword({
      user_id,
      otp: hashOtp,
      email,
    });
    // if (!exist) {
    temp = await forget.save();
    // }
    // else {
    //   temp = await ForgetPassword.findOneAndUpdate(
    //     { user_id: user_id, email: email },
    //     {
    //       $set: {
    //         otp: hashOtp,
    //       },
    //     },
    //     { upsert: true }
    //   );
    // }

    if (temp) {
      let info = transporter.sendMail({
        from: EMAIL_FROM,
        to: email,
        subject: "Forget Password Otp",
        text: "Your password reseting Otp   " + temp_otp,
      });
    }

    res.status(200).json({ success: true, data: `Otp sent to ${email}` });
  },

  async verifyOtp(req, res, next) {
    const { user_id, email, otp, password } = req.body;

    const exist = await ForgetPassword.findOne({
      user_id: user_id,
      email: email,
    });

    const isMatch = await bcrypt.compare(otp.toString(), exist.otp);

    if (email == exist.email && isMatch) {
      res.status(200).json({ success: true, data: `Otp verified sucessfully` });
    }
  },
  async resetPassword(req,res,next) {
    const { user_id, email, otp, password, confirm_new_password } = req.body;
    const hashedPassword = await bcrypt.hash(password.toString(), 10);
  
    if (password == confirm_new_password) {
      const filter = { _id: req.params.id };
      const updateDocument = {
        $set: {
          password: hashedPassword
        },
      };

      const options = { upsert: true };

      const result = await User.findOneAndUpdate(
        filter,
        updateDocument,
        options
      );
      
      res
        .status(200)
        .json({ success: true, data: `Password updated sucessfully!` });
    } else {
        return next(CustomErrorHandler.alreadyExist(`New Password & Confirm New Password do not match!`));
    }
  },
};

export default ForgetPasswordController;
