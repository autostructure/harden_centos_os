Facter.add(:yum_repos) do
  confine :kernel => 'Linux'

  setcode do
    Dir["/etc/yum.repos.d/*"]
  end
end
