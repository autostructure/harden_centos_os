Facter.add(:guid_executables) do
  confine kernel: 'Linux'

  setcode do
    files_string = Facter::Core::Execution.execute('df --local -P | awk \'NR != 1 {print $6}\' | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -2000')

    files_string.split("\n")
  end
end
