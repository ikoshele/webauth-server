export function errorHandler(err, req, res) {
    console.log(err);
    res.status(err.statusCode || 500).json({ errorName: err.name,
        errorMessage: err.message,
        errors: err.errors });
}