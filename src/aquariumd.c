// this is the aquarium daemon
// we don't want only the root user to be able to create/run programs inside aquariums, so this daemon, which runs as root, basically waits until another process asks it to create a new aquarium from a sanctioned list of images
// this process can be a user process, so long as that user is part of the "stoners" group (the group allowed to create aquariums)
// it also creates a user in the aquarium with the same privileges and home directory (*only if asked, it can also create a separate home directory) as the user which asked for the aquarium to be created

// awesome video on message queues: https://www.youtube.com/watch?v=OYqX19lPb0A

#include <bob.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <err.h>
#include <mqueue.h>

#define MQ_NAME "/aquariumd"

#define MAX_MESSAGES 10 // not yet sure what this signifies
#define MESSAGE_SIZE 256

int main(void) {
	// TODO make sure another aquariumd process isn't already running

	// TODO make sure the "stoners" group exists, and error if not

	// make sure a message queue named $MQ_NAME doesn't already exist

	mode_t permissions = /* TODO figure this out (yeah, I still don't know this stuff by heart, big deal 😤) */;

	struct mq_attr attr = {
		.mq_flags = O_BLOCK,
		.mq_maxmsg = MAX_MESSAGES,
		.mq_msgsize = MESSAGE_SIZE,
		.mq_curmsgs = 0,
	};

	if (mq_open(MQ_NAME, O_CREAT | O_EXCL, permissions, &attr) < 0) {
		if (errno == EEXIST) {
			errx(EXIT_FAILURE, "Message queue named \"" MQ_NAME "\" already exists");
		}

		errx(EXIT_FAILURE, "Failed detecting message queue: %s", strerror(errno));
	}

	// create message queue

	mqd_t mq = mq_open(MQ_NAME, O_CREAT | O_RDWR, mode, attr);

	if (mq < 0) {
		errx(EXIT_FAILURE, "Failed to create message queue: %s", strerror(errno));
	}

	// block while waiting for messages on the message queue

	while (1) {
		uint8_t buf[MESSAGE_SIZE];
		__attribute__((unused)) int priority; // we don't care about priority

		ssize_t len = mq_receive(mqm, buf, sizeof buf, &priority);

		if (errno == EAGAIN) {
			continue;
		}

		if (errno == ETIMEDOUT) {
			errx(EXIT_FAILURE, "Receiving on the message queue timed out");
		}

		if (len < 0) {
			errx(EXIT_FAILURE, "mq_receive: %s", strerror(errno));
		}
	}

	// don't forget to remove the message queue completely

	mq_close(mq); // not sure if this is completely necessary, doesn't matter
	mq_unlink(MQ_NAME);

	return 0;
}