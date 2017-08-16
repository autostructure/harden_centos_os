Facter.add(:log_files) do
  confine kernel: 'Linux'

  setcode do
    Dir["/var/log/**/*"]
  end
end
