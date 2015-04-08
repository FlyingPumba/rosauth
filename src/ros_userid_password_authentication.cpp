/*!
 * \file ros_userid_password_authentication.cpp
 * \brief Provides authentication via an user ID and a password.
 *
 * This node provides a service call that can be used to authenticate a user to use the ROS server.
 * This code allows to generate a node for user authentication using an user id and a password.
 *
 * Based on code from Russell Toris, WPI - rctoris@wpi.edu
 */

#include <fstream>
#include <openssl/sha.h>
#include <ros/ros.h>
#include <rosauth/Authentication.h>
#include <rosauth/UserIdPasswordAuthentication.h>
#include <rosauth/md5.h>
#include <sstream>
#include <string>

using namespace std;
using namespace ros;

/*!
 * \def SECRET_FILE_USERS
 * The ROS parameter name for the file that contains the users and passwords. We do not store the actual
 * string in the parameter server as the parameter server itself may not be secure.
 */
#define SECRET_FILE_USERS "/rosauth/ros_userid_password_authentication/secret_file_users_location"

/*!
 * \def MISSING_PARAMETER
 * Error code for a missing SECRET_FILE_PARAM ROS parameter.
 */
#define MISSING_PARAMETER -1

/*!
 * \def FILE_IO_ERROR
 * Error code for an IO error when reading the secret file.
 */
#define FILE_IO_ERROR -2

/*!
 * \def INVALID_SECRET
 * Error code for an invalid secret string.
 */
#define INVALID_SECRET -3


// the secret user file with MD5 hashes
string secret_users_file;


bool authenticate(rosauth::UserIdPasswordAuthentication::Request &req, rosauth::UserIdPasswordAuthentication::Response &res)
{
  // get user and md5 of the password
  string client_user = req.user;
  string client_md5_pass = md5(req.pass);

  ifstream f;
  f.open(secret_users_file.c_str(), ifstream::in);

  if (f.is_open())
  {
    string line;
    while (getline(f, line))
    {
      istringstream iss(line);
      string user, md5_pass;
      if (!(iss >> user >> md5_pass))
        break; // wrong formatted file
      else
      {
        if (client_user == user && client_md5_pass == md5_pass)
        {
          ROS_INFO("User '%s' successfully authenticated", client_user.c_str());
          // user is authenticated
          res.authenticated = true;
          return true;
        }
      }
    }
    f.close();
  }
  else
  {
    ROS_ERROR("Could not read from file '%s'", secret_users_file.c_str());
    return FILE_IO_ERROR;
  }

  ROS_INFO("User '%s' failed authentication", client_user.c_str());
  res.authenticated = false;
  return true;
}

/*!
 * Creates and runs the ros_userid_password_authentication node.
 *
 * \param argc argument count that is passed to ros::init
 * \param argv arguments that are passed to ros::init
 * \return EXIT_SUCCESS if the node runs correctly
 */
int main(int argc, char **argv)
{
  // initialize ROS and the node
  init(argc, argv, "ros_userid_password_authentication");
  NodeHandle node;



  if (!node.getParam(SECRET_FILE_USERS, secret_users_file))
  {
    ROS_ERROR("Parameter '%s' not found.", SECRET_FILE_USERS);
    return MISSING_PARAMETER;
  }
  else
  {
    ServiceServer userService = node.advertiseService("authenticate_userid_password", authenticate);
    ROS_INFO("ROS User Authentication Using ID Password Server Started");
    spin();
    return EXIT_SUCCESS;
  }
}
