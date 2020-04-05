/// `Operation` error kind represented by `OperationError`.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ErrorKind {
	/// Failed to parse data for `Operation::Establish`.
	IncorrectEstablishData,
	/// Operation type to perform is not&nbsp;defined.
	UndefinedOperation,
}
