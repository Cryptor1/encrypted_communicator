use serde_json::error::Category;

#[derive(Debug, PartialEq)]
pub enum Kind {
	/// Failed to obtain the&nbsp;size of JSON structure data to deserialize.
	NoSize,
	/// Represents one of possible errors that can occur when serializing or
	/// deserializing JSON data.
	///
	/// # Parameters
	/// `Category` &#x2013; The cause of an&nbsp;error.
	Json(Category),
	/// Parsed JSON contains inappropriate data instead of the&nbsp;expected one
	/// according to conventions.
	HeaderData,
	/// Content data is not&nbsp;appropriate in the&nbsp;context of `Operation`
	/// being performed in a&nbsp;given communication session.
	ContentData,
	/// Obtained unique identifier of another `Communicator` is not&nbsp;valid.
	InvalidUid,
	/// Failed to generate unique identifier for a&nbsp;given communicator.
	UidGeneration,
}
