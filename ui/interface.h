#ifndef UI_H
#define UI_H
#include <string>

// overridable for GUI or CLI
class UI
{
	public:
		UI() = default;
	
		virtual void raise_warning(std::string msg) = 0;

		virtual void raise_error(std::string msg) = 0;

		virtual void print(std::string msg) = 0;


};

#endif /* UI_H */
