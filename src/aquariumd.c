// this is the aquarium daemon
// we don't want only the root user to be able to create/run programs inside aquariums, so this daemon, which runs as root, basically waits until another process asks it to create a new aquarium from a sanctioned list of images
// this process can be a user process, so long as that user is part of the "stoners" group (the group allowed to create aquariums)
// it also creates a user in the aquarium with the same privileges and home directory (*only if asked, it can also create a separate home directory) as the user which asked for the aquarium to be created

// awesome video on message queues: https://www.youtube.com/watch?v=OYqX19lPb0A
// (totally underrated channel/guy btw)

#include <bob.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <err.h>
#include <grp.h>
#include <mqueue.h>

#define MQ_NAME "/aquariumd"

#define MAX_MESSAGES 10 // not yet sure what this signifies
#define MESSAGE_SIZE 256

#define OP_CREATE_AQUARIUM 0x63
#define OP_DELETE_AQUARIUM 0x64

// in the future, it may be interesting to add some more of these (e.g. so that aquariums don't have access to '/dev' - you'd want to restrict this access because, even if you trust the aquarium, you're considerably increasing the attack surface in case for e.g. a root service is exploited by a misbehaving user process)

#define FLAG_LINK_HOME 0b01
#define FLAG_LINK_TMP  0b10

typedef struct {
	uint8_t op;
	uint8_t flags;

	// what kind of aquarium should be created?
	// this field follows the following format: 'arch.os.version'
	// e.g., 'amd64.ubuntu.focal', 'amd64.freebsd.12'
	// it's ignored if 'cmd_t.op == OP_DELETE_AQUARIUM'

	uint8_t kind[256];

	// where should the aquarium be created or deleted?
	// this must be in a directory owned by the user issuing the command

	uint8_t path[256];
} cmd_t;

static inline void __process_cmd(uid_t uid, cmd_t* cmd) {
	if (cmd->flags & FLAG_LINK_HOME) {
		errx(EXIT_FAILURE, "Command's 'FLAG_LINK_HOME' flag set (not yet implemented)\n");
	}

	if (cmd->flags & FLAG_LINK_TMP) {
		errx(EXIT_FAILURE, "Command's 'FLAG_LINK_TMP' flag set (not yet implemented)\n");
	}

	// TODO
}

int main(void) {
	// make sure the "stoners" group exists, and error if not

	int group_len = getgroups(0, NULL);

	gid_t* gids = malloc(group_len * sizeof *gids);
	getgroups(group_len, gids);

	gid_t stoners_gid = -1 /* i.e., no "stoners" group */;

	for (int i = 0; i < group_len; i++) {
		gid_t gid = gids[group_len];
		struct group* group = getgrgid(gid); // don't need to free this

		if (strcmp(group->gr_name, "stoners") == 0) {
			stoners_gid = gid;
			break;
		}
	}

	if (stoners_gid < 0) {
		errx(EXIT_FAILURE, "Couldn't find \"stoners\" group\n");
	}

	// make sure a message queue named $MQ_NAME doesn't already exist
	// this means that we don't need to check if another aquariumd process is running, because it fails if the message queue has already been created by another process

	mode_t permissions = 0420; // owner ("root") can only read, group ("stoners") can only write, and others can do neither - istg it's a complete coincidence this ends up as 420 in octal - at least I ain't finna forget the permission numbers any time soon 🤣

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

	mqd_t mq = mq_open(MQ_NAME, O_CREAT | O_RDWR, permissions, attr);

	if (mq < 0) {
		errx(EXIT_FAILURE, "Failed to create message queue: %s", strerror(errno));
	}

	// set group ownership to the "stoners" group

	if (fchown(mq, getuid() /* most likely gonna be root */, stoners_gid) < 0) {
		errx(EXIT_FAILURE, "fchown: %s\n", strerror(errno));
	}

	// setup message queue notification signal
	// thanks @qookie 😄

	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);

	sigprocmask(SIG_BLOCK, &set, NULL);

	// block while waiting for messages on the message queue

	while (1) {
		siginfo_t info;
		sigwaitinfo(&set, &info, NULL);

		// received a message, run a bunch of sanity checks on it

		if (info.si_mqd != mq) {
			continue;
		}

		uid_t uid = info.si_uid;

		// read message data & process it

		cmd_t cmd;
		__attribute__((unused)) int priority; // we don't care about priority

	retry: // fight me, this is more readable than a loop

		ssize_t len = mq_receive(mq, &cmd, sizeof cmd, &priority);

		if (errno == EAGAIN) {
			goto retry;
		}

		if (errno == ETIMEDOUT) {
			errx(EXIT_FAILURE, "Receiving on the message queue timed out");
		}

		if (len < 0) {
			errx(EXIT_FAILURE, "mq_receive: %s", strerror(errno));
		}

		__process_cmd(uid, &cmd);
	}

	// don't forget to remove the message queue completely

	mq_close(mq); // not sure if this is completely necessary, doesn't matter
	mq_unlink(MQ_NAME);

	return 0;
}