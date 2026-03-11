import ParentToken from "../../models/parentToken.model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import StudentModel from "../../models/Student.model.js";
import Parentmodel from "../../models/parent.model.js";
import Joi from "joi";
import Schoolmodel from "../../models/School.model.js";
import nodemailer from "nodemailer";

dotenv.config();

const signupSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  studentcodeinparent: Joi.string().required(),
  role: Joi.string().default("ولي أمر"),
  phone: Joi.string().required(),
  schoolCode: Joi.string().required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const forgetPasswordSchema = Joi.object({
  email: Joi.string().email().required(),
  newPassword: Joi.string().min(6).required(),
  confirmPassword: Joi.string().valid(Joi.ref("newPassword")).required(),
});

export const signup = async (req, res) => {
  try {
    // Validate request body
    const { error } = signupSchema.validate(req.body);
    if (error)
      return res.status(400).json({ message: error.details[0].message });

    const {
      name,
      email,
      password,
      studentcodeinparent,
      role,
      phone,
      schoolCode,
    } = req.body;

    // Check if student exists
    const student = await StudentModel.findOne({
      studentCode: studentcodeinparent,
    });
    if (!student) {
      return res
        .status(404)
        .json({ message: "كود الطالب الذي ادخلته غير صالح" });
    }
    const school = await Schoolmodel.findOne({ code: schoolCode });
    if (!school) {
      return res.status(404).json({ message: "كود المدرسة غير صالح" });
    }
    // Check if parent already exists
    const existingParent = await Parentmodel.findOne({ email });
    if (existingParent) {
      return res.status(400).json({ message: "البريد الالكتروني مسجل بالفعل" });
    }

    // Create new parent - password will be hashed by the pre-save hook
    const parent = new Parentmodel({
      name,
      email,
      password,
      studentcodeinparent,
      role,
      phone,
      schoolCode,
    });
    await parent.save();

    // Generate token
    const token = jwt.sign(
      {
        _id: parent._id.toString(),
        email: parent.email,
        studentCode: parent.studentcodeinparent,
        name: parent.name,
        role: parent.role,
        phone: parent.phone,
        schoolCode: parent.schoolCode,
        studentName: student.name,
      },
      process.env.JWT_SECRET,
    );

    // Save token
    const parentToken = new ParentToken({
      parentId: parent._id,
      token,
      schoolCode: parent.schoolCode,
    });
    await parentToken.save();

    res
      .status(201)
      .json({
        message: `تم انشاء حساب كولي امر للطالب ${student.name} بنجاح`,
        token,
      });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const login = async (req, res) => {
  try {
    // Validate request body
    const { error } = loginSchema.validate(req.body);
    if (error)
      return res.status(400).json({ message: error.details[0].message });

    const { email, password } = req.body;

    // Find parent
    const parent = await Parentmodel.findOne({ email });
    if (!parent) {
      return res.status(401).json({ message: "البريد الالكتروني غير صالح" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, parent.password);
    if (!isMatch) {
      return res.status(401).json({ message: "كلمة المرور غير صالحة" });
    }

    // Get stored token
    const parentToken = await ParentToken.findOne({ parentId: parent._id });
    if (!parentToken) {
      return res.status(404).json({ message: "Token not found" });
    }

    res.json({ message: "تم تسجيل الدخول بنجاح", token: parentToken.token });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const forgetPassword = async (req, res) => {
  try {
    // Validate request body
    const { error } = forgetPasswordSchema.validate(req.body);
    if (error)
      return res.status(400).json({ message: error.details[0].message });

    const { email, newPassword, confirmPassword } = req.body;

    // Check if passwords match
    if (newPassword !== confirmPassword) {
      return res
        .status(400)
        .json({
          message: "كلمة المرور الجديدة وتأكيد كلمة المرور غير متطابقين",
        });
    }

    // Find parent by email
    const parent = await Parentmodel.findOne({ email });
    if (!parent) {
      return res.status(404).json({ message: "البريد الالكتروني غير مسجل" });
    }

    // Update password - will be hashed by pre-save hook
    parent.password = newPassword;
    await parent.save();

    res.json({ message: "تم تغيير كلمة المرور بنجاح" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const updateParent = async (req, res) => {
  try {
    const updates = Object.keys(req.body);
    const allowedUpdates = ["name", "email", "password"];
    const isValidOperation = updates.every((update) =>
      allowedUpdates.includes(update),
    );

    if (!isValidOperation) {
      return res.status(400).json({ message: "حدث خطاء في التحديث" });
    }

    const parent = await Parentmodel.findById(req.params.id);
    if (!parent) {
      return res.status(404).json({ message: "ولي امر هذا الطالب غير موجود" });
    }

    updates.forEach((update) => (parent[update] = req.body[update]));
    await parent.save();

    res.json(parent);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const deleteParent = async (req, res) => {
  try {
    const parent = await Parentmodel.findByIdAndDelete(req.params.id);
    if (!parent) {
      return res.status(404).json({ message: "ولي امر هذا الطالب غير موجود" });
    }

    // Delete associated token
    await ParentToken.findOneAndDelete({ parentId: parent._id });

    res.json({ message: "تم حذف ولي الامر بنجاح" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const generateVerificationCode = async (req, res) => {
  try {
    const { email } = req.body;

    // Find the teacher
    const parent = await Parentmodel.findOne({ email });
    if (!parent) {
      return res.status(404).json({ message: "ولي الامر غير موجود" });
    }

    // Check if verification code already exists
    if (parent.verifiedCode) {
      return res.status(400).json({
        message: "لديك بالفعل رمز تحقق صالح. يرجى استخدام الرمز المرسل مسبقاً ",
      });
    }

    // Generate a random 6-digit code
    const verificationCode = Math.floor(
      100000 + Math.random() * 900000,
    ).toString();

    // Save the code to database
    parent.verifiedCode = verificationCode;
    await parent.save();

    // Create transporter
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASS,
      },
    });

    // Create HTML email template
    const htmlEmail = `
        <!DOCTYPE html>
        <html dir="rtl">
        <head>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    line-height: 1.6;
                    color: #333;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #f9f9f9;
                    border-radius: 10px;
                }
                .header {
                    background-color: #4CAF50;
                    color: white;
                    padding: 20px;
                    text-align: center;
                    border-radius: 10px 10px 0 0;
                }
                .content {
                    padding: 20px;
                    background-color: white;
                    border-radius: 0 0 10px 10px;
                    text-align: center;
                    
                }
                .code {
                    font-size: 32px;
                    font-weight: bold;
                    color: #4CAF50;
                    text-align: center;
                    padding: 20px;
                    margin: 20px 0;
                    background-color: #f0f0f0;
                    border-radius: 5px;
                }
                .footer {
                    text-align: center;
                    margin-top: 20px;
                    color: #666;
                }
                .icon {
                    font-size: 48px;
                    text-align: center;
                    margin-bottom: 20px;
                    font-size: 25px;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>أندية القراءة المدرسية</h1>
                </div>
                <div class="content">
                    <div class="icon">📚</div>
                    <h2 >مرحباً ${parent.name}</h2>
                    <p>لقد تلقينا طلباً لإعادة تعيين كلمة المرور الخاصة بك. الرجاء استخدام الرمز التالي:</p>
                    <div class="code">${verificationCode}</div>
                    <p> الرجاء عدم مشاركة هذا الرمز مع أي شخص</p>
                    <div class="footer">
                        <p>مع تحيات فريق أندية القراءة المدرسية</p>
                            <p>© 2024 جميع الحقوق محفوظة </p>
                            <p style="text-decoration: none;">www.alephyaa.net</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        `;

    // Send email
    await transporter.sendMail({
      from: process.env.EMAIL,
      to: email,
      subject: "رمز التحقق - أندية القراءة المدرسية",
      html: htmlEmail,
    });

    res.status(200).json({ message: "تم إرسال رمز التحقق بنجاح" });
  } catch (error) {
    res
      .status(500)
      .json({
        message: "حدث خطأ أثناء إرسال رمز التحقق",
        error: error.message,
      });
  }
};

export const verifyCodeAndResetPassword = async (req, res) => {
  try {
    const { email, verificationCode, newPassword, confirmPassword } = req.body;

    // Validate passwords match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ message: "كلمات المرور غير متطابقة" });
    }

    // Find teacher and verify code
    const parent = await Parentmodel.findOne({
      email,
      verifiedCode: verificationCode,
    });

    if (!parent) {
      return res.status(400).json({ message: "رمز التحقق غير صحيح" });
    }

    // Update password and remove verification code
    parent.password = newPassword;
    parent.verifiedCode = undefined;
    await parent.save();

    res.status(200).json({ message: "تم تغيير كلمة المرور بنجاح" });
  } catch (error) {
    res
      .status(500)
      .json({
        message: "حدث خطأ أثناء تغيير كلمة المرور",
        error: error.message,
      });
  }
};

export const getallParentsBySchoolCode = async (req, res) => {
  try {
    // Validate school code is provided in the request body
    const { schoolCode } = req.params;
    if (!schoolCode) {
      return res.status(400).json({
        status: "خطاء",
        message: "يجب تقديم الكود المدرسي",
      });
    }

    // Find students with the specified school code
    const parents = await Parentmodel.find({
      schoolCode: schoolCode,
    });

    // Check if any students found
    if (parents.length === 0) {
      return res.status(404).json({
        status: "خطاء",
        message: "لم يتم العثور على اولياء الامور للكود المدرسي المقدم",
      });
    }

    res.status(200).json({
      status: "نجاح",
      results: parents.length,
      data: parents,
    });
  } catch (error) {
    res.status(500).json({
      status: "خطاء",
      message: "حدث خطاء اثناء استرداد اولياء: " + error.message,
    });
  }
};
