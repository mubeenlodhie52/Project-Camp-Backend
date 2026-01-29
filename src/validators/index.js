import { body } from "express-validator";

const userRegisterValidator = () => {
    return [
        body("email")
            .trim()
            .notEmpty().withMessage("Email is required.")
            .isEmail().withMessage("Email is invalid."),

        body("username")
            .trim()
            .notEmpty().withMessage("Username is required.")
            .toLowerCase()
            .isLength({ min: 3 }).withMessage("Username must be at least 3 characters long")
            .isAlphanumeric().withMessage("Username must contain only letters and numbers"),

        body("password")
            .trim()
            .notEmpty().withMessage("Password is required.")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),

        body("fullName")
            .optional()
            .trim()
            .isLength({ min: 3 })
            .withMessage("Full name must be at least 3 characters long"),
    ];
};

const userLoginValidator = () => {
    return [
        body("email")
            .optional()
            .isEmail()
            .withMessage("Email is invalid!"),

        body("username")
            .optional()
            .trim(),

        body("password")
            .notEmpty()
            .withMessage("Password is required."),
    ];
};

const userChangeCurrentPasswordValidator = () => {
    return [
        body("oldPassword").notEmpty().withMessage("Old Password is required"),
        body("newPassword").notEmpty().withMessage("New password is required")
    ]
};

const userForgotPasswordValidator = () => {
    return[
        body("email")
        .notEmpty()
        .withMessage("Email is required")
        .isEmail()
        .withMessage("Email is invalid!")
    ]
};

const userResetForgotPasswordValidator = () => {
    return[
        body("newPassword")
            .notEmpty()
            .withMessage("Password is required!")
    ]
};

export { userRegisterValidator, userLoginValidator,userChangeCurrentPasswordValidator,userForgotPasswordValidator, userResetForgotPasswordValidator};
