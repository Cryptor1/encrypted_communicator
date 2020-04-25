extern crate config;
extern crate encrypted_communicator;

use encrypted_communicator::communicator::{Communicator, ProcessedData, Uid};
use config::{Config, File};
use std::net::{TcpStream, TcpListener};
use std::io::{Read, Write};
use std::thread;
use std::collections::HashMap;
use std::time::Duration;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use regex::Regex;
use std::thread::JoinHandle;

const CONFIGURATION_FILE: &str = "tests/config/tests_config";
/// Communicator, which handles multiple connections, is going to listen on this
/// port.
const COMMUNICATOR_PORT: &str = "communicator_port";
/// Simultaneous connections to be handled by single communicator.
const CONNECTIONS_QUANTITY_SETTING: &str = "connections_quantity";
/// Messages to be transmitted and processed by each communicator.
const MESSAGES_QUANTITY_SETTING: &str = "messages_quantity";
const LOCALHOST: &str = "127.0.0.1:";
const READ_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Checks an&nbsp;ability of `Communicator` instance to handle multiple
/// connections asynchronously. Such communicator instance is called
/// _multiple&#x2011;connections communicator_ here in test.
///
/// Loads `Communicator` instance with multiple connections specified by
/// `CONNECTIONS_QUANTITY_SETTING`. Each communication side is expected to
/// produce `MESSAGES_QUANTITY_SETTING` messages. Their order and correctness is
/// checked as well.
///
/// Connections instantiating, as well as messages transmitting, is performed
/// asynchronously without any order.
#[test]
fn handle_multiple_connections_asynchronously() {
	let mut config = Config::default();
	config.merge(File::with_name(CONFIGURATION_FILE)).unwrap();
	let configuration_property_failure_message = format!(
		"Failed to fetch configuration property from `{}` file", CONFIGURATION_FILE);
	let port = config.get_str(COMMUNICATOR_PORT).expect(&configuration_property_failure_message);
	let mut address = LOCALHOST.to_owned();
	address.push_str(&port);
	let connections_quantity = config.get_int(CONNECTIONS_QUANTITY_SETTING)
		.expect(&configuration_property_failure_message);
	let messages_quantity = config.get_int(MESSAGES_QUANTITY_SETTING)
		.expect(&configuration_property_failure_message);
	let multiple_connections_communicator_uid = Uid::generate_totally_unique().unwrap();

	let multiple_connections_communicator_handle = spawn_multiple_connections_listener(
		address.to_owned(),
		multiple_connections_communicator_uid.clone(),
		connections_quantity,
		messages_quantity,
	);

	let mut single_connection_communicator_handlers = Vec::with_capacity(
		connections_quantity as usize);
	for i in 1..connections_quantity + 1 {
		let handle = spawn_single_connection_communicator(
			i.to_string(),
			address.to_owned(),
			multiple_connections_communicator_uid.clone(),
			messages_quantity,
		);
		single_connection_communicator_handlers.push(handle);
	}

	single_connection_communicator_handlers.into_iter().for_each(|handler| handler.join().unwrap());
	multiple_connections_communicator_handle.join().unwrap();
}

/// Instantiates multiple&#x2011;connections communicator and prepares handler
/// for each new connection.
/// # Parameters
/// * `address` &ndash; Address the&nbsp;instantiated listener is going to
/// listen on.
/// * `uid` &ndash; Unique identifier for `Communicator` instance, which is
/// going to handle multiple connections simultaneously.
/// * `connections_quantity` &ndash; Exact connections quantity
/// the&nbsp;instantiated listener should expect to receive.
/// * `messages_quantity` &ndash; Exact messages quantity communicator routine
/// should expect to receive per each connection.
fn spawn_multiple_connections_listener(
	address: String,
	uid: Uid,
	connections_quantity: i64,
	messages_quantity: i64,
) -> JoinHandle<()> {
	return thread::spawn(move || {
		let that_listener = TcpListener::bind(&address).unwrap();
		let (sender, receiver) = mpsc::channel();
		let mut connection_handlers = Vec::new();
		let receiver_handle = receiver_routine(
			receiver, uid, connections_quantity, messages_quantity);
		let mut connection_counter = 0;
		for stream in that_listener.incoming() {
			if stream.is_ok() {
				let stream = stream.unwrap();
				connection_handlers.push(handle_new_connection(stream, sender.clone()));
				connection_counter += 1;
				if connection_counter == connections_quantity { break }
			} else { panic!(stream.err().unwrap()) }
		}
		connection_handlers.into_iter().for_each(|handler| handler.join().unwrap());
		receiver_handle.join().unwrap();
	});
}

/// Spawns a&nbsp;connection routine for multiple&#x2011;connections
/// communicator. All data is being sent to receiver routine spawned in
/// `receiver_routine()`.
/// # Parameters
/// * `stream` &ndash; Connection to retain in spawned routine.
/// * `sender` &ndash; A channel to send the&nbsp;received data to
/// multiple&#x2011;connections communicator.
///
/// Is `spawn_multiple_connections_listener()` auxiliary.
fn handle_new_connection(
	stream: TcpStream,
	sender: Sender<(Vec<u8>, Box<dyn Write + Send>)>,
) -> JoinHandle<()> {
	return thread::spawn(move || {
		stream.set_write_timeout(Some(READ_WRITE_TIMEOUT)).unwrap();
		stream.set_read_timeout(Some(READ_WRITE_TIMEOUT)).unwrap();
		loop {
			let received_data = receive_data(Box::new(stream.try_clone().unwrap()));
			if received_data.is_empty() { break }
			sender.send((received_data.clone(), Box::new(stream.try_clone().unwrap())))
				.expect(
					"Sender does not expect to receive disconnect-related error, since it does \
						not send any additional data on successful test execution. Under \
						\"successful execution\" receiving `messages_quantity` messages is assumed",
				);
		}
	});
}

/// Is actually the&nbsp;routine with multiple&#x2011;connections communicator.
/// # Parameters
/// * `receiver` &ndash; A channel to receive data for processing.
/// * `uid` &ndash; Unique identifier for `Communicator` instance, which is
/// going to handle multiple connections simultaneously.
/// * `connections_quantity` &ndash; Exact connections quantity
/// the&nbsp;communicator should expect to handle.
/// * `messages_quantity` &ndash; Exact messages quantity the&nbsp;communicator
/// should expect to receive per each connection.
fn receiver_routine(
	receiver: Receiver<(Vec<u8>, Box<dyn Write + Send>)>,
	uid: Uid,
	connections_quantity: i64,
	messages_quantity: i64,
) -> JoinHandle<()> {
	return thread::spawn(move || {
		let communicator = Communicator::new_with_known_communicators(uid, HashMap::new());
		let mut received_messages_counter = HashMap::with_capacity(connections_quantity as usize);
		loop {
			let should_stop = is_all_messages_received(
				&received_messages_counter, messages_quantity, connections_quantity);
			if should_stop { break }
			let (received_data, mut write_instance) = match receiver
				.recv_timeout(READ_WRITE_TIMEOUT) {
				Ok(result) => result,
				Err(err) => match err {
					RecvTimeoutError::Disconnected => {
						panic!(
							"Receiver does not expect to receive disconnection signal, since it \
								shuts down by itself before such signal receiving. This receiver \
								expects to shut down itself when \
								`connection_quantity` x `messages_quantity` messages have been \
								received",
						);
					},
					_ => panic!(err),
				},
			};
			match communicator.process_incoming(&received_data).unwrap() {
				ProcessedData::Service(data, _) => {
					write_instance.write_all(&data).unwrap();
					write_instance.flush().unwrap();
				},
				ProcessedData::Communication(data, uid) => {
					let expected_message_pattern =
						r"^Communication message \d+ from communicator \d+$";
					let regex = Regex::new(expected_message_pattern).unwrap();
					let received_message = String::from_utf8_lossy(&data);
					assert!(regex.is_match(&received_message));
					let other_communicator_index = process_message(
						&received_message, &mut received_messages_counter);
					let to_send = format!(
						"Communication message for communicator {}", other_communicator_index);
					let to_send = communicator.process_outgoing(&uid, to_send.as_bytes()).unwrap();
					write_instance.write_all(&to_send).unwrap();
					write_instance.flush().unwrap();
				},
				_ => (),
			};
		}
	});
}

/// Parser for messages received by multiple&#x2011;connections communicator
/// from other communicators which have connection with the&nbsp;mentioned
/// communicator.
///
/// Is `receiver_routine()` auxiliary.
/// # Parameters
/// * `message` &ndash; Message to parse.
/// * `received_messages_counter` &ndash; Already received messages quantity per
/// communicator with a&nbsp;given indexing number. On successful parsing this
/// method increments obtained received messages quantity for
/// a&nbsp;corresponding communicator.
/// # Returns
/// Indexing number of communicator a&nbsp;message was obtained from.
fn process_message(message: &str, received_messages_counter: &mut HashMap<u32, u32>) -> u32 {
	let message_ordinal_with_communicator_id = message.split_whitespace()
		.filter(|part| part.parse::<u32>().is_ok())
		.map(|substring| substring.parse::<u32>().unwrap())
		.collect::<Vec<_>>();
	let message_ordinal_index = 0;
	let communicator_indexing_number_index = 1;
	let communicator_indexing_number = message_ordinal_with_communicator_id
		.get(communicator_indexing_number_index)
		.expect(
			"No indexing number, which represents a communicator, has been found in received \
				message",
		);
	let received_message_ordinal = message_ordinal_with_communicator_id
		.get(message_ordinal_index).expect("No message ordinal has been found in received message");
	match received_messages_counter.insert(
		*communicator_indexing_number,
		*received_message_ordinal,
	) {
		Some(value) => {
			assert_eq!(
				*received_message_ordinal, value + 1, "Unexpected message has been received");
		},
		None => assert_eq!(1, *received_message_ordinal, "Unexpected message has been received"),
	}
	return *communicator_indexing_number;
}

/// A convenience method for `receiver_routine()` which checks whether all
/// expected messages have been received from all expected connections.
/// # Parameters
/// * `received_messages_counter` &ndash; Already received messages quantity per
/// communicator with a&nbsp;given indexing number.
/// * `messages_quantity` &ndash; Exact messages quantity that are expected to
/// be received by multiple&#x2011;connections communicator from each handled
/// connection.
/// * `connections_quantity` &ndash; Exact connections quantity that are
/// expected to be handled by multiple&#x2011;connections communicator.
fn is_all_messages_received(
	received_messages_counter: &HashMap<u32, u32>,
	messages_quantity: i64,
	connections_quantity: i64,
) -> bool {
	if received_messages_counter.len() != connections_quantity as usize {
		return false;
	}
	return received_messages_counter.iter().all(|(communicator_ordinal, actual_quantity)| {
		assert!(
			*actual_quantity <= messages_quantity as u32,
			"Messages quantity received from communicator with indexing number {} is more than \
				expected. Max messages quantity is expected to be {}, while there are {} already",
			communicator_ordinal, messages_quantity, *actual_quantity,
		);
		return *actual_quantity == messages_quantity as u32;
	});
}

/// Spawns communicator routine which establishes connection with
/// multiple&#x2011;connections communicator, and performs messages
/// transmitting/processing.
/// # Parameters
/// * `indexing_number` &ndash; Indexing number used for easier distinguishing
/// an&nbsp;instance of spawned communicator from other ones while testing.
/// * `multiple_connections_communicator_address` &ndash; Listener of
/// multiple&#x2011;connections communicator to connect to.
/// * `multiple_connections_communicator_uid` &ndash; Unique identifier of
/// another (multiple&#x2011;connections communicator) to communicate with.
/// * `messages_quantity` &ndash; Exact messages quantity to transmit.
fn spawn_single_connection_communicator(
	indexing_number: String,
	multiple_connections_communicator_address: String,
	multiple_connections_communicator_uid: Uid,
	messages_quantity: i64,
) -> JoinHandle<()> {
	return thread::spawn(move || {
		let communicator: Communicator = Communicator::new().unwrap();
		let mut connection = TcpStream::connect(multiple_connections_communicator_address).unwrap();
		connection.set_read_timeout(Option::Some(READ_WRITE_TIMEOUT)).unwrap();
		connection.set_write_timeout(Option::Some(READ_WRITE_TIMEOUT)).unwrap();
		let mut data_to_send = communicator
			.request_connection(&multiple_connections_communicator_uid).unwrap();
		let mut message_counter = 0;
		loop {
			connection.write_all(&data_to_send).unwrap();
			connection.flush().unwrap();
			let received_response = receive_data(Box::new(connection.try_clone().unwrap()));
			data_to_send = match communicator.process_incoming(&received_response).unwrap() {
				ProcessedData::ConnectionEstablished(uid) => {
					assert_eq!(
						multiple_connections_communicator_uid,
						uid,
						"Connection-established response from multiple-connections communicator \
							contains incorrect UID",
					);
					message_counter += 1;
					let to_encrypt = format!(
						"Communication message {} from communicator {}",
						message_counter, indexing_number,
					);
					communicator
						.process_outgoing(
							&multiple_connections_communicator_uid,
							to_encrypt.as_bytes(),
						)
						.unwrap()
				},
				ProcessedData::Service(data, _) => data,
				ProcessedData::Communication(data, _) => {
					let expected_message = format!(
						"Communication message for communicator {}", indexing_number);
					assert_eq!(
						expected_message,
						String::from_utf8_lossy(&data),
						"Unexpected message has been received",
					);
					message_counter += 1;
					if message_counter > messages_quantity { break }
					let to_encrypt = format!(
						"Communication message {} from communicator {}",
						message_counter, indexing_number,
					);
					communicator
						.process_outgoing(
							&multiple_connections_communicator_uid,
							to_encrypt.as_bytes(),
						)
						.unwrap()
				},
				unexpected_incoming_data => panic!(unexpected_incoming_data),
			}
		}
	});
}

/// Is a convenience method to fetch data from `source`.
fn receive_data(mut source: Box<dyn Read>) -> Vec<u8> {
	let mut received_data = Vec::new();
	let mut buffer = vec![0; 4096];
	loop {
		let read_size = source.read(buffer.as_mut_slice()).unwrap();
		received_data.extend(&buffer[0..read_size]);
		if read_size == 0 || read_size < buffer.len() { break }
		else {
			buffer.clear();
			continue
		}
	}
	return received_data;
}
