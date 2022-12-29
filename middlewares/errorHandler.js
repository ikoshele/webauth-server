const fieldNameMap = {
    hashedPassword: 'password'
};
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
    console.log(err);
    if (err.name === 'SequelizeValidationError') err.statusCode = 400;
    const filteredErrors = err.errors?.map((error) => {
        return {
            message: error.message,
            path: fieldNameMap[error.path] || error.path,
        };
    });
    res.status(err.statusCode || 500).json({
        errorName: err.name,
        errorMessage: err.message,
        errors: filteredErrors
    });
}