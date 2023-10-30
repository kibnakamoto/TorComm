#ifndef CLI_H
#define CLI_H

#include <string>

#include "interface.h"

// Command Line Interface

class CLI : public UI
{
	
		virtual void raise_warning(std::string msg) override;

		virtual void raise_error(std::string msg) override;

		virtual void print(std::string msg) override;
};

#endif /* CLI_H */
