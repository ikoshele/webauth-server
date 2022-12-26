// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
    const filteredErrors = err.errors?.map((error) => {
        return {
            message: error.message,
            path: error.path,
        };
    });
    res.status(err.statusCode || 500).json({
        errorName: err.name,
        errorMessage: err.message,
        errors: filteredErrors
    });
}