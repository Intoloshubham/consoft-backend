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
    const existMail = await User.findOne({ email: email });

    if (!existMail) {
      return next(CustomSuccessHandler.customMessage({msg:"Email does not exist",status:"401"}));
    }

    const temp_otp = await CustomFunction.randomNumber();
    const hashOtp = await bcrypt.hash(temp_otp.toString(), 10);

    const forget = new ForgetPassword({
      user_id: existMail._id,
      otp: hashOtp,
      email,
    });

    temp = await forget.save();

    if (temp) {
      let info = transporter.sendMail({
        from: EMAIL_FROM,
        to: email,
        subject: "Forget Password Otp",
        text: "Your password reseting Otp   " + temp_otp,
      });
    }

    res
      .status(200)
      .json({
        success: true,
        data: { msg: `Otp sent to ${email}`, res: temp },
      });
  },

  async verifyOtp(req, res, next) {
    const { user_id, email, otp, password } = req.body;

    const existMail = await User.findOne({ _id: req.params.user_id });

    const exist = await ForgetPassword.findOne({
      user_id: req.params.user_id,
      email: existMail.email,
    });
     if (exist) {
       const isMatch = await bcrypt.compare(otp.toString(), exist.otp);
       if (existMail.email === exist.email && isMatch) {
         res.status(200).json({ success: true, data: `Otp verified sucessfully` });
   
         await ForgetPassword.deleteOne({ user_id: req.params.user_id });
         // await ForgetPassword.findByIdAndRemove({ user_id: req.params.user_id });
       } else {
         res.status(400).json({ success: false, data:{msg: `Otp not matched`,isMatch:isMatch} });
       }      
     }

  },

  async resetPassword(req, res, next) {
    const { user_id, email, otp, new_password, confirm_new_password } =
      req.body;
    const hashedPassword = await bcrypt.hash(new_password.toString(), 10);

    if (new_password == confirm_new_password) {
      const filter = { _id: req.params.user_id };
      const updateDocument = {
        $set: {
          password: hashedPassword,
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
      return next(
        CustomErrorHandler.alreadyExist(
          `New Password & Confirm New Password do not match!`
        )
      );
    }
  },
};

export default ForgetPasswordController;
