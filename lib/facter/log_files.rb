Facter.add(:log_files) do
  confine kernel: 'Linux'

  setcode do
    log_files = Dir['/var/log/**/*'].reject do |path|
      File.directory?(path)
    end

    log_files
  end
end
