/*
  Copyright (c) 2019-present, Trail of Bits, Inc.
  All rights reserved.

  This source code is licensed in accordance with the terms specified in
  the LICENSE file found in the root directory of this source tree.
*/

#include "configuration.h"
#include "faultinjector.h"
#include "utils.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>

#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <unistd.h>

#include <tob/ebpf/perfeventarray.h>

int main(int argc, char *argv[], char *envp[]) {
  auto command_line_params_exp = tob::ebpfault::parseCommandLine(argc, argv);
  if (!command_line_params_exp.succeeded()) {
    std::cerr << command_line_params_exp.error().message() << "\n";
    return 1;
  }

  auto command_line_params = command_line_params_exp.takeValue();
  static_cast<void>(command_line_params);

  if (!tob::ebpfault::configureRlimit()) {
    std::cerr << "Failed to set RLIMIT_MEMLOCK\n";
    return 1;
  }

  auto configuration_exp = tob::ebpfault::Configuration::create(
      command_line_params.configuration_path);

  if (!configuration_exp.succeeded()) {
    std::cerr << configuration_exp.error().message() << "\n";
    return 1;
  }

  auto configuration = configuration_exp.takeValue();

  auto perf_event_array_exp = tob::ebpf::PerfEventArray::create(10);

  if (!perf_event_array_exp.succeeded()) {
    std::cerr << perf_event_array_exp.error().message() << "\n";
    return 1;
  }

  auto perf_event_array = perf_event_array_exp.takeValue();

  tob::ebpfault::FaultInjector::ProcessIDFilter pid_filter;
  sem_t *execve_semaphore{nullptr};

  if (command_line_params.opt_pid_list.has_value()) {
    pid_filter.process_id_list = command_line_params.opt_pid_list.value();

    if (command_line_params.except_pid_list) {
      pid_filter.type =
          tob::ebpfault::FaultInjector::ProcessIDFilter::Type::Except;
    } else {
      pid_filter.type =
          tob::ebpfault::FaultInjector::ProcessIDFilter::Type::Matching;
    }

  } else {
    auto semaphore_name = "ebpfault_" + std::to_string(getpid());
    execve_semaphore =
        sem_open(semaphore_name.c_str(), O_CREAT | O_EXCL, 0600, 0);

    if (execve_semaphore == SEM_FAILED) {
      std::cerr << "Failed to create the semaphore\n";
      return 1;
    }

    auto child_pid = fork();

    if (child_pid == 0) {
      auto exec_command_line =
          command_line_params.opt_exec_command_line.value();

      auto path = exec_command_line.at(0);
      // exec_command_line.erase(exec_command_line.begin());

      std::vector<char *> exec_argv;
      for (auto &param : exec_command_line) {
        exec_argv.push_back(&param[0]);
      }

      exec_argv.push_back(nullptr);

      execve_semaphore = sem_open(semaphore_name.c_str(), O_CREAT, 0600, 0);

      if (execve_semaphore == SEM_FAILED) {
        std::cerr << "Failed to create the semaphore\n";
        return 1;
      }

      if (sem_wait(execve_semaphore) < 0) {
        std::cerr << "Semaphore wait has failed\n";
        return 1;
      }

      execve(path.c_str(), exec_argv.data(), envp);
      throw std::runtime_error("exec has failed");
    }

    pid_filter.process_id_list = {child_pid};
    pid_filter.type =
        tob::ebpfault::FaultInjector::ProcessIDFilter::Type::Matching;
  }

  std::vector<tob::ebpfault::FaultInjector::Ref> fault_injector_list;

  std::cout << "Generating fault injectors...\n\n";

  for (const auto &config : *configuration) {
    std::cout << " > " << config.name << "\n";
    std::cout << "   Error list:\n";

    for (const auto &error : config.error_list) {
      std::cout << "   - " << std::setw(3) << std::setfill(' ')
                << static_cast<int>(error.probability) << "% => "
                << tob::ebpfault::describeFaultValue(error.exit_code) << "\n";
    }

    auto fault_injector_exp = tob::ebpfault::FaultInjector::create(
        *perf_event_array.get(), config, pid_filter);

    if (!fault_injector_exp.succeeded()) {
      std::cerr << fault_injector_exp.error().message() << "\n";
      return 1;
    }

    auto fault_injector = fault_injector_exp.takeValue();
    fault_injector_list.push_back(std::move(fault_injector));

    std::cout << "\n";
  }

  if (execve_semaphore != nullptr) {
    if (sem_post(execve_semaphore) < 0) {
      std::cerr << "Failed to post to the semaphore\n";
      return 1;
    }
  }

  for (;;) {
    std::size_t running_process_count = 0U;

    for (auto pid : pid_filter.process_id_list) {
      if (kill(pid, 0) == 0) {
        ++running_process_count;
      }
    }

    if (running_process_count == 0U) {
      std::cout << "All processes have been terminated\n";
      break;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  if (execve_semaphore != nullptr) {
    sem_close(execve_semaphore);
  }

  std::cout << "Exiting...\n";
  return 0;
}
